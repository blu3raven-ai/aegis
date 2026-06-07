"""Aggregated GET /api/v1/findings endpoint — Phase 55.

Unifies open/closed findings across all four scanners (deps, container, sast,
secrets) into a single cursor-paginated REST response. Filters and sort live
in the service layer; this module only parses query params, enforces auth,
and shapes errors.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from src.db.engine import get_session
from src.db.models import Finding
from src.findings.service import (
    FindingsListFilters,
    _finding_to_dict,
    assign_finding,
    list_assignable_users,
    list_findings,
    summarize_findings,
)
from src.settings.audit import record_event
from src.settings.router import require_permission
from src.settings.team_access import actor_user_id
from src.shared.lifecycle import VALID_DISMISS_REASONS, bulk_dismiss, dismiss_finding
from src.shared.scope import get_user_asset_ids

router = APIRouter(prefix="/api/v1", tags=["findings"])


@router.get("/findings/summary")
async def findings_summary_endpoint(
    request: Request,
    org_id: str | None = Query(None, description="Optional org identifier — used as a UI narrowing filter on top of asset-scoped access"),
) -> dict[str, Any]:
    """Return cross-scanner KPI counts (open, severity buckets, fixed-recent, dismissed)."""
    ctx = {"user_id": request.state.user_sub, "role": request.state.user_role}
    async with get_session() as session:
        asset_ids = await get_user_asset_ids(session, ctx)
        return await summarize_findings(session=session, asset_ids=asset_ids)


def _parse_csv_list(value: str | None) -> list[str] | None:
    """Split a comma-separated query param into a non-empty list, or None."""
    if not value:
        return None
    parts = [v.strip() for v in value.split(",") if v.strip()]
    return parts or None


def _parse_iso_or_none(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"invalid first_seen_after: {value}") from exc


@router.get("/findings")
async def list_findings_endpoint(
    request: Request,
    org_id: str | None = Query(None, description="Optional org identifier — used as a UI narrowing filter on top of asset-scoped access"),
    severity: str | None = Query(None, description="CSV of severities (critical,high,medium,low)"),
    scanner: str | None = Query(None, description="CSV of scanner shorthand (deps,container,sast,secrets)"),
    state: str | None = Query(None, description="CSV of finding states (open,closed,dismissed)"),
    q: str | None = Query(None, description="Free-text search on title/cve/path/package"),
    cve: str | None = Query(None, description="Exact CVE id match (e.g. CVE-2021-44228)"),
    repo: str | None = Query(None, description="Exact match on Finding.repo (e.g. 'org/repo')"),
    sort: str = Query("severity", description="Sort key: severity | created_at | updated_at"),
    direction: str = Query("desc", description="Sort direction: asc | desc"),
    limit: int = Query(50, ge=1, le=200, description="Page size — capped at 200"),
    cursor: str | None = Query(None, description="Opaque cursor returned by a previous call"),
    page: int = Query(1, ge=1, description="1-indexed page number; ignored when cursor is provided"),
    archived: bool | None = Query(
        None,
        description="Filter by archive state. true returns only archived findings; false or omitted hides them (default).",
    ),
    first_seen_after: str | None = Query(None, description="ISO8601 — only findings first seen at or after this timestamp"),
    cwe: str | None = Query(None, description="CWE identifier (e.g. CWE-502)"),
    kev: bool | None = Query(None, description="If true, only findings whose CVE is in CISA KEV"),
    epss_min: float | None = Query(None, ge=0.0, le=1.0, description="Minimum EPSS percentile"),
    risk_score_min: int | None = Query(None, ge=0, le=100, description="Minimum risk score (0-100)"),
    assignee: str | None = Query(None, max_length=255, description="Filter to findings assigned to this user id"),
) -> dict[str, Any]:
    """Return a cursor-paginated list of findings across all scanners.

    Scoped to the assets the requesting user may access. The optional org_id
    query param acts as an additional UI narrowing filter on top of the
    asset-based access boundary — it is no longer the primary scope.
    """
    ctx = {"user_id": request.state.user_sub, "role": request.state.user_role}

    try:
        async with get_session() as session:
            asset_ids = await get_user_asset_ids(session, ctx)
            filters = FindingsListFilters(
                org_id=org_id or "",
                asset_ids=asset_ids,
                severity=_parse_csv_list(severity),
                scanner=_parse_csv_list(scanner),
                state=_parse_csv_list(state),
                q=q,
                cve=cve,
                repo=repo,
                sort=sort,
                direction=direction,
                limit=limit,
                cursor=cursor,
                archived=archived,
                first_seen_after=_parse_iso_or_none(first_seen_after),
                cwe=cwe,
                kev=kev,
                epss_min=epss_min,
                risk_score_min=risk_score_min,
                assignee_user_id=assignee,
                page=page,
            )
            return await list_findings(filters, session)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/findings/{finding_id}/dismiss")
async def dismiss_finding_by_id_endpoint(finding_id: int, request: Request) -> dict[str, Any]:
    """Dismiss a single finding by its numeric id. Resolves tool / org / identity_key
    by loading the row, then dispatches to the unified lifecycle helper."""
    require_permission(request, "run_scans")
    body = await request.json()
    reason = body.get("reason")
    comment = body.get("comment")
    if reason not in VALID_DISMISS_REASONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid dismiss reason. Must be one of: {sorted(VALID_DISMISS_REASONS)}",
        )

    async with get_session() as session:
        result = await session.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalars().first()

    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")

    user_id = actor_user_id(request) or "unknown"
    if finding.asset_id:
        dismiss_finding(finding.tool, finding.identity_key, reason, user_id, comment, asset_id=finding.asset_id)
    else:
        dismiss_finding(finding.tool, finding.identity_key, reason, user_id, comment, org=finding.org)
    return {"ok": True}


@router.post("/findings/bulk_dismiss")
async def bulk_dismiss_findings_endpoint(request: Request) -> dict[str, Any]:
    """Dismiss many findings in one call. Groups by (tool, org) and delegates to
    `bulk_dismiss` per group, since the lifecycle helper is scoped to one tool
    per invocation."""
    require_permission(request, "run_scans")
    body = await request.json()
    raw_ids = body.get("ids")
    reason = body.get("reason")
    comment = body.get("comment")

    if not isinstance(raw_ids, list) or not raw_ids:
        raise HTTPException(status_code=400, detail="ids must be a non-empty list of finding ids")
    if len(raw_ids) > 1000:
        raise HTTPException(status_code=400, detail="Too many ids (max 1000 per request)")
    try:
        ids = [int(x) for x in raw_ids]
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail="ids must be integers") from exc
    if reason not in VALID_DISMISS_REASONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid dismiss reason. Must be one of: {sorted(VALID_DISMISS_REASONS)}",
        )

    async with get_session() as session:
        result = await session.execute(select(Finding).where(Finding.id.in_(ids)))
        rows = result.scalars().all()

    # Group identity_keys by (tool, asset_id) for asset-scoped dismiss.
    # Secrets findings have asset_id=NULL and are grouped by tool alone.
    groups_asset: dict[tuple[str, str], list[str]] = defaultdict(list)
    groups_secrets: dict[str, list[str]] = defaultdict(list)  # tool -> keys
    for f in rows:
        if f.asset_id:
            groups_asset[(f.tool, f.asset_id)].append(f.identity_key)
        else:
            groups_secrets[f.tool].append(f.identity_key)

    user_id = actor_user_id(request) or "unknown"
    updated_total = 0
    for (tool, asset_id), keys in groups_asset.items():
        updated_total += bulk_dismiss(tool, keys, reason, user_id, comment, asset_ids=[asset_id])
    for tool, keys in groups_secrets.items():
        # Secrets have no asset_id; bulk_dismiss with secrets=True uses NULL asset_id path
        updated_total += bulk_dismiss(tool, keys, reason, user_id, comment, secrets=True)

    return {"ok": True, "updated": updated_total}


@router.patch("/findings/{finding_id}/assignee")
async def assign_finding_endpoint(finding_id: int, request: Request) -> dict[str, Any]:
    """Set or clear the assignee on a finding.

    Body: `{"assignee_user_id": "user-id" | null}`. A null/empty value clears
    the assignment; any other value must match an existing user.
    """
    require_permission(request, "review_findings")
    body = await request.json()
    if "assignee_user_id" not in body:
        raise HTTPException(status_code=400, detail="assignee_user_id is required (use null to unassign)")

    raw = body["assignee_user_id"]
    if raw is not None and not isinstance(raw, str):
        raise HTTPException(status_code=400, detail="assignee_user_id must be a string or null")

    try:
        async with get_session() as session:
            finding, previous = await assign_finding(finding_id, raw, session)
            payload = _finding_to_dict(finding)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    actor = actor_user_id(request) or "unknown"
    record_event(
        action="finding.assigned",
        actor_user_id=actor,
        target=str(finding_id),
        metadata={"from": previous, "to": payload["assignee_user_id"]},
    )
    return {"ok": True, "finding": payload}


@router.get("/findings/assignable-users")
async def list_assignable_users_endpoint(
    request: Request,
    q: str | None = Query(None, max_length=255, description="Case-insensitive substring on username or email"),
    limit: int = Query(20, ge=1, le=50, description="Page size — capped at 50"),
) -> dict[str, Any]:
    """Return up to `limit` active users matching `q` for the assignee picker.

    Gated on `review_findings` — narrower than the user-management API so
    triagers can resolve a username without inheriting `view_users`. Returns
    only the fields the picker renders (id, username, email).
    """
    require_permission(request, "review_findings")
    async with get_session() as session:
        users = await list_assignable_users(session, q=q, limit=limit)
    return {"users": users}
