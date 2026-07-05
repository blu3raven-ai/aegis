"""REST endpoint for /api/v1/scans/{scan_id}."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import CANCEL_SCANS, VIEW_FINDINGS
from src.scans.models import FindingCounts, ScanDetailResponse, VerificationSummary
from src.scans.service import cancel_scan, get_scan

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


@router.get("/{scan_id}", response_model=ScanDetailResponse, summary="Get scan status")
async def get_scan_endpoint(
    scan_id: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> ScanDetailResponse:
    """Fetch a single scan_run by id.

    Authorization: the caller must hold ``view_findings`` AND have the scan's
    underlying asset_id in scope (via team membership or direct grant). Out-
    of-scope scans return 404 to avoid leaking existence to a probing caller.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    detail = await get_scan(scan_id=scan_id, asset_ids=asset_ids)
    if detail is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanDetailResponse(
        scan_id=detail.scan_id,
        repo_id=detail.repo_id,
        commit_sha=detail.commit_sha,
        scanner_types=detail.scanner_types,
        status=detail.status,
        submitted_at=detail.submitted_at.isoformat(),
        submitted_by=detail.submitted_by,
        started_at=detail.started_at.isoformat() if detail.started_at else None,
        finished_at=detail.finished_at.isoformat() if detail.finished_at else None,
        finding_counts=FindingCounts(**detail.finding_counts) if detail.finding_counts else None,
        error=detail.error,
        archived=detail.archived,
        verification_summary=(
            VerificationSummary(**detail.verification_summary)
            if detail.verification_summary else None
        ),
    )


@router.post("/{scan_id}/cancel", summary="Cancel an active scan")
async def cancel_scan_endpoint(
    scan_id: str,
    request: Request,
    _: None = Depends(Permission(CANCEL_SCANS)),
) -> JSONResponse:
    """Stop a queued/running/ingesting scan and cancel the runner job behind it.

    Authorization: the caller must hold ``cancel_scans`` AND have the scan's
    underlying asset_id in scope. Out-of-scope or missing scans return 404 to
    avoid leaking existence.

    Cancelling is idempotent: calling cancel on a scan that's already in a
    terminal state (completed/failed/cancelled) returns 200 with
    ``{"ok": True, "already_terminal": True}`` so the UI doesn't have to race
    the SSE update to know which button to enable.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    actor_user_id = getattr(request.state, "user_sub", None)
    result = await cancel_scan(
        scan_id=scan_id, asset_ids=asset_ids, actor_user_id=actor_user_id,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if result == "already_terminal":
        return JSONResponse({"ok": True, "already_terminal": True})
    return JSONResponse({"ok": True, "scanId": result})
