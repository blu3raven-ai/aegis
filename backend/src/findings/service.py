"""Cross-scanner findings aggregation service — Phase 55.

Single source of truth for the unified findings list endpoint. Reads from the
`findings` table (which already stores rows from all four scanners with a
discriminating `tool` column) so no SQL UNION or Python-side merge is required.

The service is intentionally pure data access — no HTTP concerns. The router
layer translates filter strings and shapes the response.
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding

# Internal tool name (DB) -> public scanner shorthand (API surface).
# Public shorthand matches the CLI/UI vocabulary; the DB uses the longer form
# that the per-scanner ingest paths write.
_TOOL_TO_PUBLIC = {
    "dependencies": "deps",
    "container_scanning": "container",
    "code_scanning": "sast",
    "secrets": "secrets",
}
_PUBLIC_TO_TOOL = {v: k for k, v in _TOOL_TO_PUBLIC.items()}

VALID_SCANNERS = frozenset(_PUBLIC_TO_TOOL.keys())
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})
VALID_STATES = frozenset({"open", "closed", "dismissed", "fixed"})
VALID_SORTS = frozenset({"severity", "created_at", "updated_at"})

# Ordering value used to sort severities — higher = more severe.
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Server-side cap so a malicious or buggy client can't exhaust memory.
MAX_LIMIT = 200
DEFAULT_LIMIT = 50

# Cap free-text search length so an attacker can't force expensive ILIKE scans.
MAX_Q_LENGTH = 200


@dataclass
class FindingsListFilters:
    org_id: str
    severity: list[str] | None = None
    scanner: list[str] | None = None
    state: list[str] | None = None
    q: str | None = None
    cve: str | None = None
    sort: str = "severity"
    direction: str = "desc"
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None


def _normalize_filters(filters: FindingsListFilters) -> FindingsListFilters:
    """Apply caps and lowercase normalisation. Raises ValueError on invalid input."""
    if not filters.org_id:
        raise ValueError("org_id is required")

    severity = None
    if filters.severity:
        severity = [s.lower() for s in filters.severity if s]
        bad = [s for s in severity if s not in VALID_SEVERITIES]
        if bad:
            raise ValueError(f"invalid severity: {bad}")

    scanner = None
    if filters.scanner:
        scanner = [s.lower() for s in filters.scanner if s]
        bad = [s for s in scanner if s not in VALID_SCANNERS]
        if bad:
            raise ValueError(f"invalid scanner: {bad}")

    state = None
    if filters.state:
        state = [s.lower() for s in filters.state if s]
        bad = [s for s in state if s not in VALID_STATES]
        if bad:
            raise ValueError(f"invalid state: {bad}")

    sort = (filters.sort or "severity").lower()
    if sort not in VALID_SORTS:
        raise ValueError(f"invalid sort: {sort}")

    direction = (filters.direction or "desc").lower()
    if direction not in ("asc", "desc"):
        raise ValueError(f"invalid direction: {direction}")

    limit = filters.limit if filters.limit and filters.limit > 0 else DEFAULT_LIMIT
    limit = min(limit, MAX_LIMIT)

    q: str | None = None
    if filters.q:
        q = filters.q.strip()[:MAX_Q_LENGTH] or None

    cve: str | None = None
    if filters.cve:
        cve = filters.cve.strip()[:64] or None

    return FindingsListFilters(
        org_id=filters.org_id,
        severity=severity,
        scanner=scanner,
        state=state,
        q=q,
        cve=cve,
        sort=sort,
        direction=direction,
        limit=limit,
        cursor=filters.cursor,
    )


def _encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str) -> dict[str, Any]:
    pad = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + pad)
        return json.loads(raw)
    except (binascii.Error, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("invalid cursor") from exc


def _sort_columns(sort: str, direction: str):
    """Return the list of ORDER BY columns for the given sort + direction.

    Always tie-breaks on `Finding.id` so cursor pagination is deterministic
    when the primary sort key has duplicates.
    """
    desc = direction == "desc"
    if sort == "severity":
        # Sort by severity rank — Postgres CASE expression so we can use the
        # ordinal rather than the lexicographic order of the severity string.
        sev_rank = func.coalesce(
            func.nullif(
                func.lower(Finding.severity),
                "",
            ),
            "low",
        )
        # Build a CASE that maps each severity to its rank.
        from sqlalchemy import case
        rank_expr = case(
            (func.lower(Finding.severity) == "critical", 4),
            (func.lower(Finding.severity) == "high", 3),
            (func.lower(Finding.severity) == "medium", 2),
            (func.lower(Finding.severity) == "low", 1),
            else_=0,
        )
        primary = rank_expr.desc() if desc else rank_expr.asc()
        secondary = Finding.id.desc() if desc else Finding.id.asc()
        return [primary, secondary]
    if sort == "created_at":
        primary = Finding.created_at.desc() if desc else Finding.created_at.asc()
        secondary = Finding.id.desc() if desc else Finding.id.asc()
        return [primary, secondary]
    # updated_at
    primary = Finding.updated_at.desc() if desc else Finding.updated_at.asc()
    secondary = Finding.id.desc() if desc else Finding.id.asc()
    return [primary, secondary]


def _cursor_predicate(cursor_payload: dict[str, Any], sort: str, direction: str):
    """Build the WHERE clause that resumes a paginated query after a cursor.

    Keyset pagination — selects rows strictly after the cursor's (sort_value, id)
    according to the sort direction. Comparing only on `id` would be wrong when
    the sort column has ties.
    """
    last_id = cursor_payload.get("id")
    if last_id is None:
        return None

    if sort == "severity":
        last_rank = cursor_payload.get("rank")
        if last_rank is None:
            return None
        from sqlalchemy import case
        rank_expr = case(
            (func.lower(Finding.severity) == "critical", 4),
            (func.lower(Finding.severity) == "high", 3),
            (func.lower(Finding.severity) == "medium", 2),
            (func.lower(Finding.severity) == "low", 1),
            else_=0,
        )
        if direction == "desc":
            return or_(
                rank_expr < last_rank,
                and_(rank_expr == last_rank, Finding.id < last_id),
            )
        return or_(
            rank_expr > last_rank,
            and_(rank_expr == last_rank, Finding.id > last_id),
        )

    last_ts = cursor_payload.get("ts")
    if last_ts is None:
        return None
    last_dt = datetime.fromisoformat(last_ts) if isinstance(last_ts, str) else last_ts
    col = Finding.created_at if sort == "created_at" else Finding.updated_at
    if direction == "desc":
        return or_(col < last_dt, and_(col == last_dt, Finding.id < last_id))
    return or_(col > last_dt, and_(col == last_dt, Finding.id > last_id))


def _build_next_cursor(last: Finding, sort: str) -> str:
    if sort == "severity":
        rank = _SEVERITY_RANK.get((last.severity or "").lower(), 0)
        return _encode_cursor({"rank": rank, "id": last.id})
    if sort == "created_at":
        ts = last.created_at.isoformat() if last.created_at else None
        return _encode_cursor({"ts": ts, "id": last.id})
    ts = last.updated_at.isoformat() if last.updated_at else None
    return _encode_cursor({"ts": ts, "id": last.id})


def _build_where_clauses(filters: FindingsListFilters) -> list:
    clauses: list = [Finding.org == filters.org_id]
    if filters.severity:
        clauses.append(func.lower(Finding.severity).in_(filters.severity))
    if filters.scanner:
        internal_tools = [_PUBLIC_TO_TOOL[s] for s in filters.scanner]
        clauses.append(Finding.tool.in_(internal_tools))
    if filters.state:
        clauses.append(Finding.state.in_(filters.state))
    if filters.cve:
        # Exact CVE match — checks both possible detail keys used by different
        # scanner ingest paths (dependencies uses "cve_id", others use "cve").
        cve_upper = filters.cve.upper()
        clauses.append(
            or_(
                Finding.detail["cve_id"].astext == cve_upper,
                Finding.detail["cve"].astext == cve_upper,
            )
        )
    if filters.q:
        # ILIKE on the relevant detail fields and the identity_key fallback.
        # Length already capped in _normalize_filters so this is bounded.
        like = f"%{filters.q}%"
        clauses.append(
            or_(
                Finding.identity_key.ilike(like),
                Finding.repo.ilike(like),
                Finding.detail["title"].astext.ilike(like),
                Finding.detail["rule_name"].astext.ilike(like),
                Finding.detail["package_name"].astext.ilike(like),
                Finding.detail["file_path"].astext.ilike(like),
                Finding.detail["path"].astext.ilike(like),
                Finding.detail["cve_id"].astext.ilike(like),
                Finding.detail["cve"].astext.ilike(like),
            )
        )
    return clauses


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Serialise a Finding to the public response shape.

    The public response collapses scanner-specific detail fields into the
    common shape documented by the endpoint. `package` is meaningful only
    for dependency/container findings; `file_path` and `line` are meaningful
    only for SAST/secrets findings — both default to None when absent.
    """
    detail: dict = finding.detail or {}

    title = (
        detail.get("title")
        or detail.get("rule_name")
        or detail.get("package_name")
        or finding.identity_key
    )

    cve = detail.get("cve_id") or detail.get("cve") or None

    package = None
    pkg_name = detail.get("package_name")
    pkg_version = detail.get("package_version") or detail.get("current_version")
    if pkg_name:
        package = f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name

    file_path = detail.get("file_path") or detail.get("path") or None
    line_raw = detail.get("start_line") or detail.get("line")
    try:
        line = int(line_raw) if line_raw is not None else None
    except (ValueError, TypeError):
        line = None

    return {
        "id": str(finding.id),
        "scanner": _TOOL_TO_PUBLIC.get(finding.tool, finding.tool),
        "severity": (finding.severity or "").lower() or None,
        "state": finding.state,
        "title": title,
        "cve": cve,
        "package": package,
        "file_path": file_path,
        "line": line,
        "repo": finding.repo,
        "org_id": finding.org,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
    }


async def list_findings(
    raw_filters: FindingsListFilters,
    session: AsyncSession,
) -> dict[str, Any]:
    """Return paginated findings + total count for the given filters.

    Cursor pagination: the response includes `next_cursor` when more rows
    exist past the current page. `total_count` is the unpaginated total —
    a separate COUNT(*) query so the UI can display "1–50 of 12,345".
    """
    filters = _normalize_filters(raw_filters)

    where = _build_where_clauses(filters)

    cursor_clause = None
    if filters.cursor:
        payload = _decode_cursor(filters.cursor)
        cursor_clause = _cursor_predicate(payload, filters.sort, filters.direction)

    base_where = and_(*where)

    count_stmt = select(func.count()).select_from(Finding).where(base_where)
    count_result = await session.execute(count_stmt)
    total = int(count_result.scalar() or 0)

    page_where = base_where
    if cursor_clause is not None:
        page_where = and_(base_where, cursor_clause)

    page_stmt = (
        select(Finding)
        .where(page_where)
        .order_by(*_sort_columns(filters.sort, filters.direction))
        .limit(filters.limit + 1)
    )
    page_result = await session.execute(page_stmt)
    rows = list(page_result.scalars().all())

    has_more = len(rows) > filters.limit
    page = rows[: filters.limit]
    next_cursor = _build_next_cursor(page[-1], filters.sort) if has_more and page else None

    return {
        "findings": [_finding_to_dict(f) for f in page],
        "next_cursor": next_cursor,
        "total_count": total,
    }
