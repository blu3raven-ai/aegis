"""REST endpoint for /api/v1/releases — pre-release scans scoped to the caller's assets."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.engine import get_session
from src.releases.schemas import (
    BlockerDiffRow,
    ReleaseDetail,
    ReleaseListResponse,
    ReleaseSummary,
    ReleaseTriggeredBy,
)
from src.releases.service import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    ReleaseListFilters,
    get_release,
    list_releases,
)
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/releases", tags=["releases"])


@router.get("", response_model=ReleaseListResponse, summary="List recent pre-release scans")
async def list_releases_endpoint(
    request: Request,
    repo_id: str | None = Query(None, description="Filter to a single repo (org/repo)"),
    status: str | None = Query(None, description="queued | running | completed | failed"),
    verdict: str | None = Query(None, description="go | warn | no_go | pending | unknown"),
    limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT),
    cursor: str | None = Query(None, description="Opaque pagination token"),
) -> ReleaseListResponse:
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)

    filters = ReleaseListFilters(
        asset_ids=asset_ids,
        repo_id=repo_id,
        status=status,
        verdict=verdict,
        limit=limit,
        cursor=cursor,
    )

    async with get_session() as session:
        try:
            result = await list_releases(filters, session)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    releases = [
        ReleaseSummary(
            scan_id=r["scan_id"],
            repo_id=r["repo_id"],
            repo=r["repo"],
            ref=r["ref"],
            commit_sha=r["commit_sha"],
            short_sha=r["short_sha"],
            verdict=r["verdict"],
            blocker_count=r["blocker_count"],
            warn_count=r["warn_count"],
            scanner_count=r["scanner_count"],
            status=r["status"],
            started_at=r["started_at"],
            finished_at=r["finished_at"],
            triggered_by=ReleaseTriggeredBy(**r["triggered_by"]),
        )
        for r in result["releases"]
    ]

    return ReleaseListResponse(releases=releases, next_cursor=result["next_cursor"])


@router.get(
    "/{scan_id}",
    response_model=ReleaseDetail,
    summary="Get a single release with blocker diff against baseline",
)
async def get_release_endpoint(scan_id: str, request: Request) -> ReleaseDetail:
    require_permission(request, "view_findings")
    asset_ids = await resolve_asset_ids_from_request(request)

    async with get_session() as session:
        detail = await get_release(scan_id=scan_id, asset_ids=asset_ids, session=session)

    # Out-of-scope and missing scan share the 404 surface so access boundaries
    # don't leak through HTTP status codes — same convention as scans/router.py.
    if detail is None:
        raise HTTPException(status_code=404, detail="Release not found")

    summary = detail.summary
    return ReleaseDetail(
        scan_id=summary.scan_id,
        repo_id=summary.repo_id,
        repo=summary.repo,
        ref=summary.ref,
        commit_sha=summary.commit_sha,
        short_sha=summary.short_sha,
        verdict=summary.verdict,
        blocker_count=summary.blocker_count,
        warn_count=summary.warn_count,
        scanner_count=summary.scanner_count,
        status=summary.status,
        started_at=summary.started_at,
        finished_at=summary.finished_at,
        triggered_by=ReleaseTriggeredBy(**summary.triggered_by),
        baseline_scan_id=detail.baseline_scan_id,
        baseline_ref=detail.baseline_ref,
        baseline_taken_at=detail.baseline_taken_at,
        scanners_run=detail.scanners_run,
        blockers_diff=[BlockerDiffRow(**row.__dict__) for row in detail.blockers_diff],
        improvements=[BlockerDiffRow(**row.__dict__) for row in detail.improvements],
    )
