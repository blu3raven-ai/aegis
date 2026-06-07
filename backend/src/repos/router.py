"""REST endpoints for repos asset management — Phase 27.

Provides:
  GET /api/v1/repos          — list monitored repos with scan coverage summary
  GET /api/v1/repos/{asset_id} — detail for a single repo, keyed by asset_id UUID
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from src.db.engine import async_session_factory
from src.repos.service import RepoService, RepoSummary, RepoDetail
from src.scans.models import ScanRequest, ScanSubmissionResponse
from src.scans.service import submit_scan
from src.settings.router import require_permission
from src.shared.scope import get_user_asset_ids

router = APIRouter(prefix="/api/v1/repos", tags=["repos"])


def _summary_to_dict(s: RepoSummary) -> dict[str, Any]:
    return {
        "asset_id": s.asset_id,
        "display_name": s.display_name,
        "last_scanned_sha": s.last_scanned_sha,
        "manifest_set_hash": s.manifest_set_hash,
        "last_scanned_at": s.last_scanned_at.isoformat() if s.last_scanned_at else None,
        "findings_count_by_severity": s.findings_count_by_severity,
        "scanners_with_coverage": s.scanners_with_coverage,
        "coverage_status": s.coverage_status,
        "source_url": s.source_url,
    }


def _detail_to_dict(d: RepoDetail) -> dict[str, Any]:
    base = _summary_to_dict(d)
    base["scan_history"] = [
        {
            "scan_id": r.scan_id,
            "scanner_type": r.scanner_type,
            "status": r.status,
            "started_at": r.started_at,
            "duration_ms": r.duration_ms,
            "findings_count": r.findings_count,
        }
        for r in d.scan_history
    ]
    base["active_findings"] = [
        {
            "id": f.id,
            "tool": f.tool,
            "severity": f.severity,
            "state": f.state,
            "identity_key": f.identity_key,
            "asset_id": f.asset_id,
            "first_seen_at": f.first_seen_at,
            "last_seen_at": f.last_seen_at,
        }
        for f in d.active_findings
    ]
    base["default_branch"] = d.default_branch
    return base


@router.get("")
async def list_repos(
    request: Request,
    since_days: int | None = None,
    has_critical: bool | None = None,
    limit: int = 100,
) -> JSONResponse:
    """List monitored repos scoped to the requesting user's asset visibility."""
    require_permission(request, "view_findings")
    ctx = {"user_id": request.state.user_sub, "role": getattr(request.state, "user_role", "viewer")}
    async with async_session_factory() as db:
        asset_ids = await get_user_asset_ids(db, ctx)
    summaries = RepoService.list_repos(
        asset_ids=asset_ids,
        since_days=since_days,
        has_critical=has_critical,
        limit=limit,
    )
    return JSONResponse({"repos": [_summary_to_dict(s) for s in summaries]})


@router.get("/{asset_id}")
def get_repo(
    request: Request,
    asset_id: str,
) -> JSONResponse:
    """Return detail for a single repo identified by its asset_id UUID."""
    require_permission(request, "view_findings")
    detail = RepoService.get_repo(asset_id)
    if detail is None:
        return JSONResponse({"error": "repo not found"}, status_code=404)
    return JSONResponse(_detail_to_dict(detail))


@router.post(
    "/{asset_id}/scan",
    response_model=ScanSubmissionResponse,
    status_code=202,
    summary="Trigger a pre-release scan",
)
async def trigger_scan(
    asset_id: str,
    body: ScanRequest,
    request: Request,
) -> ScanSubmissionResponse:
    require_permission(request, "run_scans")
    user_id = request.state.user_sub

    submission = await submit_scan(
        asset_id=asset_id,
        commit_sha=body.commit_sha,
        scanner_types=body.scanner_types,
        user_id=user_id,
    )
    if submission is None:
        raise HTTPException(status_code=404, detail="Repo not found")

    return ScanSubmissionResponse(
        scan_id=submission.scan_id,
        repo_id=submission.repo_id,
        commit_sha=submission.commit_sha,
        scanner_types=submission.scanner_types,
        status=submission.status,
        submitted_at=submission.submitted_at.isoformat(),
        submitted_by=submission.submitted_by,
    )
