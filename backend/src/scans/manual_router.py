"""POST /api/v1/scans/manual — user-triggered pre-release scan from the UI.

Polymorphic over asset type. The handler accepts asset_id + optional
type-specific fields and lets submit_scan() route to the per-type dispatcher
based on Asset.type. Validation errors (scanner_types not applicable, missing
commit_sha for repos) surface as 422; unsupported asset types currently
without a wired dispatcher surface as 501.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request

from src.audit_log.recorder import ActorInfo, RequestContext, get_recorder
from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import RUN_SCANS
from src.scans.models import ManualScanRequest, ScanSubmissionResponse
from src.scans.service import ScannerNotApplicableError, submit_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.post(
    "/manual",
    response_model=ScanSubmissionResponse,
    status_code=202,
    summary="Trigger a manual scan (any source type)",
)
async def trigger_manual_scan(
    body: ManualScanRequest,
    request: Request,
    _: None = Depends(Permission(RUN_SCANS)),
) -> ScanSubmissionResponse:
    asset_ids = await resolve_asset_ids_from_request(request)
    if body.asset_id not in asset_ids:
        # 404 (not 403) when caller can't see the asset — avoids leaking existence.
        raise HTTPException(status_code=404, detail="Source not found")

    try:
        submission = await submit_scan(
            asset_id=body.asset_id,
            user_id=request.state.user_sub,
            commit_sha=body.commit_sha,
            image_digest=body.image_digest,
            scanner_types=body.scanner_types,
        )
    except ScannerNotApplicableError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except NotImplementedError as e:
        raise HTTPException(status_code=501, detail=str(e))

    if submission is None:
        raise HTTPException(status_code=404, detail="Source not found")

    try:
        get_recorder().record(
            action="scan.triggered",
            resource_type="scan_run",
            resource_id=submission.scan_id,
            actor=ActorInfo(
                user_id=getattr(request.state, "user_sub", None) or None,
                role=str(getattr(request.state, "user_role", "") or ""),
            ),
            metadata={
                "triggered_by": "user",
                "asset_id": body.asset_id,
                "commit_sha": body.commit_sha,
                "image_digest": body.image_digest,
                "scanner_types": body.scanner_types,
            },
            request=RequestContext(
                method="POST",
                path=str(request.url.path),
                ip=getattr(request.client, "host", None) if request.client else None,
                user_agent=request.headers.get("user-agent"),
            ),
        )
    except Exception:
        # Audit failures must never break a real scan submission.
        logger.exception("audit_log: scan.triggered emit failed for %s", submission.scan_id)

    return ScanSubmissionResponse(
        scan_id=submission.scan_id,
        repo_id=submission.repo_id,
        commit_sha=submission.commit_sha,
        scanner_types=submission.scanner_types,
        status=submission.status,
        submitted_at=submission.submitted_at.isoformat(),
        submitted_by=submission.submitted_by,
    )
