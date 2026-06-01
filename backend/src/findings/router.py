"""Aggregated GET /api/v1/findings endpoint — Phase 55.

Unifies open/closed findings across all four scanners (deps, container, sast,
secrets) into a single cursor-paginated REST response. Filters and sort live
in the service layer; this module only parses query params, enforces auth,
and shapes errors.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.engine import get_session
from src.findings.service import FindingsListFilters, list_findings

router = APIRouter(prefix="/api/v1", tags=["findings"])


def _parse_csv_list(value: str | None) -> list[str] | None:
    """Split a comma-separated query param into a non-empty list, or None."""
    if not value:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    return parts or None


@router.get("/findings")
async def list_findings_endpoint(
    request: Request,
    org_id: str = Query(..., description="Required org identifier — every query is scoped to this org"),
    severity: str | None = Query(None, description="CSV of severities (critical,high,medium,low)"),
    scanner: str | None = Query(None, description="CSV of scanner shorthand (deps,container,sast,secrets)"),
    state: str | None = Query(None, description="CSV of finding states (open,closed,dismissed)"),
    q: str | None = Query(None, description="Free-text search on title/cve/path/package"),
    cve: str | None = Query(None, description="Exact CVE id match (e.g. CVE-2021-44228)"),
    sort: str = Query("severity", description="Sort key: severity | created_at | updated_at"),
    direction: str = Query("desc", description="Sort direction: asc | desc"),
    limit: int = Query(50, ge=1, le=200, description="Page size — capped at 200"),
    cursor: str | None = Query(None, description="Opaque cursor returned by a previous call"),
) -> dict[str, Any]:
    """Return a cursor-paginated list of findings across all scanners for an org.

    Per-org scoping is mandatory — the vision doc forbids cross-org correlation
    and there is no admin override on this endpoint.
    """
    filters = FindingsListFilters(
        org_id=org_id,
        severity=_parse_csv_list(severity),
        scanner=_parse_csv_list(scanner),
        state=_parse_csv_list(state),
        q=q,
        cve=cve,
        sort=sort,
        direction=direction,
        limit=limit,
        cursor=cursor,
    )

    try:
        async with get_session() as session:
            return await list_findings(filters, session)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
