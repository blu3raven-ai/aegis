"""POST /api/v1/sources/{source_id}/scans/trigger — backend-mediated CI trigger."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from src.api_keys.auth import require_scope_and_source
from src.shared.rate_limit import rate_limit
from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.db.engine import get_session
from src.db.models import Asset
from src.scans.service import (
    cancel_older_queued_for_pr,
    find_inflight_scan,
    submit_ci_scan,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sources", tags=["scans-trigger"])


@dataclass
class _ApiKeyView:
    id: int
    scopes: list[str]
    allowed_source_ids: list[str] | None


class TriggerScanRequest(BaseModel):
    commit_sha: str = Field(..., min_length=4, max_length=64, pattern=r"^[0-9a-fA-F]{4,64}$")
    branch: str | None = Field(None, max_length=255)
    pr_number: int | None = Field(None, ge=1)
    trigger_metadata: dict | None = None


@router.post(
    "/{source_id}/scans/trigger",
    summary="Trigger a scan from CI",
    status_code=202,
)
async def trigger_scan_from_ci(
    source_id: str,
    body: TriggerScanRequest,
    request: Request,
) -> dict:
    rate_limit(key=f"scan_trigger:{source_id}", max_requests=1, window_seconds=10)

    # The api_keys middleware (mounted in main.py) has already verified the
    # bearer token and populated request.state. This endpoint is API-key-only:
    # reject any caller without an api_key_id on state.
    api_key_id = getattr(request.state, "api_key_id", None)
    if api_key_id is None:
        raise HTTPException(status_code=401, detail="api_key_required")
    api_key = _ApiKeyView(
        id=api_key_id,
        scopes=list(getattr(request.state, "api_key_scopes", []) or []),
        allowed_source_ids=getattr(request.state, "api_key_allowed_source_ids", None),
    )

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
