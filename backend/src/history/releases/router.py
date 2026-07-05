"""REST endpoints for the releases surface — list + detail.

Replaces the previous GraphQL fields ``activity.releases`` and
``activity.release``. List is a cursor-paginated query with a stable shape;
detail is a single-resource read with nested diff arrays — both are textbook
REST fits per the API style decision rules.

Scope is fail-closed: empty ``asset_ids`` returns an empty page (list) or 404
(detail) so access boundaries don't leak through the response code.
"""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import VIEW_FINDINGS
from src.db.helpers import run_db
from src.history.releases.service import (
    DEFAULT_LIMIT,
    MAX_LIMIT,
    BlockerDiffRowData,
    ReleaseListFilters,
    get_release,
    list_releases,
)

router = APIRouter(prefix="/api/v1/history/releases", tags=["history"])


def _diff_to_dict(row: BlockerDiffRowData) -> dict[str, Any]:
    return asdict(row)


@router.get("")
async def list_releases_endpoint(
    request: Request,
    repo_id: Optional[str] = None,
    status: Optional[str] = None,
    verdict: Optional[str] = None,
    limit: int = DEFAULT_LIMIT,
    cursor: Optional[str] = None,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> dict[str, Any]:
    asset_ids = await resolve_asset_ids_from_request(request)
    if not asset_ids:
        return {"releases": [], "next_cursor": None}

    clamped = max(1, min(limit, MAX_LIMIT))

    filters = ReleaseListFilters(
        asset_ids=asset_ids,
        repo_id=repo_id,
        status=status,
        verdict=verdict,
        limit=clamped,
        cursor=cursor,
    )

    async def _query(session):
        return await list_releases(filters, session)

    try:
        return run_db(_query)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{scan_id}")
async def get_release_endpoint(
    scan_id: str,
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> dict[str, Any]:
    asset_ids = await resolve_asset_ids_from_request(request)

    async def _query(session):
        return await get_release(scan_id=scan_id, asset_ids=asset_ids, session=session)

    detail = run_db(_query)
    if detail is None:
        raise HTTPException(status_code=404, detail="release not found")

    summary = detail.summary
    return {
        "scan_id": summary.scan_id,
        "repo_id": summary.repo_id,
        "repo": summary.repo,
        "ref": summary.ref,
        "commit_sha": summary.commit_sha,
        "short_sha": summary.short_sha,
        "verdict": summary.verdict,
        "blocker_count": summary.blocker_count,
        "warn_count": summary.warn_count,
        "scanner_count": summary.scanner_count,
        "status": summary.status,
        "started_at": summary.started_at,
        "finished_at": summary.finished_at,
        "triggered_by": summary.triggered_by,
        "baseline_scan_id": detail.baseline_scan_id,
        "baseline_ref": detail.baseline_ref,
        "baseline_taken_at": detail.baseline_taken_at,
        "scanners_run": list(detail.scanners_run),
        "blockers_diff": [_diff_to_dict(r) for r in detail.blockers_diff],
        "improvements": [_diff_to_dict(r) for r in detail.improvements],
    }
