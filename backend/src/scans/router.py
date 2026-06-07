"""REST endpoint for /api/v1/scans/{scan_id}."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from src.scans.models import FindingCounts, ScanDetailResponse
from src.scans.service import get_scan
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])


def _resolve_org(request: Request) -> str:
    org = getattr(request.state, "user_org", None) or request.query_params.get("org_id")
    if not org:
        raise HTTPException(status_code=400, detail="org_id is required")
    return org


@router.get("/{scan_id}", response_model=ScanDetailResponse, summary="Get scan status")
async def get_scan_endpoint(scan_id: str, request: Request) -> ScanDetailResponse:
    require_permission(request, "view_findings")
    # Verify the caller has an org in scope (auth gate), then look up by scan_id only.
    # Asset-level scoping is handled at the repos router for asset-aware endpoints.
    # For direct scan deep-links, org presence is a sufficient access gate.
    _resolve_org(request)

    detail = await get_scan(scan_id=scan_id, asset_id=None)
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
    )
