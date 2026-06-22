"""POST /api/v1/scans/ci — backend-mediated CI trigger (api-key auth)."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request
from sqlalchemy import select

from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.auth.credentials.auth import require_scope_and_source
from src.assets.refs import repo_ref
from src.assets.service import upsert_asset
from src.db.engine import get_session
from src.db.models import Asset
from src.scans.models import CIScanRequest
from src.scans.service import (
    cancel_older_queued_for_pr,
    find_inflight_scan,
    submit_ci_scan,
)
from src.shared.rate_limit import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@dataclass
class _ApiKeyView:
    id: int
    scopes: list[str]
    allowed_source_ids: list[str] | None


async def _resolve_source_id(body: CIScanRequest, api_key: _ApiKeyView) -> str:
    """Return the source (asset) id for this CI scan.

    Prefers an explicit ``source_id``. Otherwise resolves the repo to its asset
    via the canonical ``external_ref`` (so it dedupes against repos discovered by
    a connection / manual upload), auto-creating one if none exists. New assets
    are only created for unrestricted keys — a key scoped to specific sources may
    not mint a source outside its allowlist.
    """
    if body.source_id:
        return body.source_id

    owner, _, name = (body.repo or "").partition("/")
    if not owner or not name:
        raise HTTPException(status_code=400, detail="invalid repo (expected 'owner/name')")
    try:
        ref = repo_ref(body.source_type or "", owner, name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    async with get_session() as session:
        existing = (await session.execute(
            select(Asset).where(Asset.external_ref == ref)
        )).scalar_one_or_none()
        if existing is not None:
            return existing.id
        # No asset yet — only an unrestricted key may auto-create one.
        if api_key.allowed_source_ids:
            raise HTTPException(
                status_code=403,
                detail={"error": "source_not_in_scope", "repo": body.repo},
            )
        return await upsert_asset(
            session,
            type="repo",
            source="byo_import",
            external_ref=ref,
            display_name=f"{owner}/{name}",
            metadata={"created_via": "ci"},
        )


@router.post(
    "/ci",
    summary="Trigger a scan from CI",
    status_code=202,
)
async def trigger_scan_from_ci(
    body: CIScanRequest,
    request: Request,
) -> dict:
    api_key_id = getattr(request.state, "api_key_id", None)
    if api_key_id is None:
        raise HTTPException(status_code=401, detail="api_key_required")
    api_key = _ApiKeyView(
        id=api_key_id,
        scopes=list(getattr(request.state, "api_key_scopes", []) or []),
        allowed_source_ids=getattr(request.state, "api_key_allowed_source_ids", None),
    )

    # Guard the scope before resolving — so a key missing the scope can't
    # auto-create a source as a side effect.
    if "scan:trigger" not in api_key.scopes:
        raise HTTPException(status_code=403, detail={"error": "missing_scope", "missing_scope": "scan:trigger"})

    source_id = await _resolve_source_id(body, api_key)
    rate_limit(key=f"scan_trigger:{source_id}", max_requests=1, window_seconds=10)

    err = require_scope_and_source(api_key, scope="scan:trigger", source_id=source_id)
    if err is not None:
        raise HTTPException(status_code=403, detail=err)

    async with get_session() as session:
        asset = (await session.execute(
            select(Asset).where(Asset.id == source_id)
        )).scalar_one_or_none()
    if asset is None:
        raise HTTPException(status_code=404, detail="source_not_found")
    if asset.archived:
        raise HTTPException(status_code=409, detail={"error": "source_disabled"})

    inflight = await find_inflight_scan(
        org="", source_id=source_id, commit_sha=body.commit_sha,
    )
    if inflight is not None:
        return {
            "scan_id": inflight.id,
            "status": inflight.status,
            "status_url": f"/api/v1/scans/{inflight.id}",
            "deduplicated": True,
        }

    submission = await submit_ci_scan(
        org="",
        source_id=source_id,
        commit_sha=body.commit_sha,
        branch=body.branch,
        pr_number=body.pr_number,
        api_key_id=api_key.id,
        trigger_metadata=body.trigger_metadata,
    )
    if body.pr_number is not None:
        await cancel_older_queued_for_pr(
            org="",
            source_id=source_id,
            pr_number=body.pr_number,
            keep_scan_id=submission.scan_id,
        )

    try:
        get_recorder().record(
            action="scan.triggered",
            resource_type="scan_run",
            resource_id=submission.scan_id,
            actor=ActorInfo(user_id=f"api_key:{api_key.id}"),
            metadata={
                "triggered_by": "ci",
                "source_id": source_id,
                "commit_sha": body.commit_sha,
                "branch": body.branch,
                "pr_number": body.pr_number,
            },
            request=RequestContext(
                method="POST",
                path=str(request.url.path),
                ip=getattr(request.client, "host", None) if request.client else None,
            ),
        )
    except Exception:
        logger.exception("audit_log: scan.triggered emit failed for %s", submission.scan_id)

    return {
        "scan_id": submission.scan_id,
        "status": "queued",
        "status_url": f"/api/v1/scans/{submission.scan_id}",
    }
