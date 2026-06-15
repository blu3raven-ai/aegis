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
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from sqlalchemy import and_, false as sa_false, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Finding, KevEntry, User
from src.shared.archived_filter import exclude_archived, only_archived

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

# Concrete verdict values stored in Finding.verdict.
VALID_VERDICTS = frozenset({"confirmed", "needs_verify", "possible", "ruled_out"})

# Accepted ?verdict= filter values. "legacy" matches verdict IS NULL
# (findings ingested before LLM verification ran); "all" disables the filter.
_VALID_VERDICT_FILTERS = VALID_VERDICTS | frozenset({"legacy", "all"})
VALID_SORTS = frozenset(
    {"severity", "severity_age", "epss", "risk_score", "newest", "oldest", "created_at", "updated_at"}
)

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
    asset_ids: list[str] = field(default_factory=list)
    severity: list[str] | None = None
    scanner: list[str] | None = None
    state: list[str] | None = None
    q: str | None = None
    cve: str | None = None
    # Exact-match filter against Finding.repo. Single slug ("org/repo") — the
    # findings page uses a dropdown rather than free-text, so we don't bother
    # with a multi-value or LIKE form here.
    repo: str | None = None
    sort: str = "severity"
    direction: str = "desc"
    limit: int = DEFAULT_LIMIT
    cursor: str | None = None
    # Two-state archived view: None/False → hide archived (default user-facing
    # behaviour), True → show ONLY archived rows for archive-review surfaces.
    # There is intentionally no "include both" mode here — compliance flows
    # belong in the reports endpoint via include_archived=True.
    archived: bool | None = None
    first_seen_after: datetime | None = None
    cwe: str | None = None
    kev: bool | None = None
    epss_min: float | None = None
    risk_score_min: int | None = None
    assignee_user_id: str | None = None
    page: int = 1
    # None defaults to hiding ruled_out; "all" disables the filter entirely.
    verdict: str | None = None


def _normalize_filters(filters: FindingsListFilters) -> FindingsListFilters:
    """Apply caps and lowercase normalisation. Raises ValueError on invalid input."""
    if not filters.asset_ids and not filters.org_id:
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

    # Same length cap as the legacy Finding.repo column so we never accept a
    # value that couldn't have matched a real row anyway.
    repo: str | None = None
    if filters.repo:
        repo = filters.repo.strip()[:255] or None

    first_seen_after = filters.first_seen_after  # caller passes a real datetime or None

    cwe = filters.cwe.strip().upper()[:32] if filters.cwe else None
    kev = bool(filters.kev) if filters.kev is not None else None
    epss_min = min(max(float(filters.epss_min), 0.0), 1.0) if filters.epss_min is not None else None
    risk_score_min = (
        min(max(int(filters.risk_score_min), 0), 100) if filters.risk_score_min is not None else None
    )

    assignee_user_id: str | None = None
    if filters.assignee_user_id:
        assignee_user_id = filters.assignee_user_id.strip()[:255] or None

    page = max(1, int(filters.page or 1))

    verdict: str | None = None
    if filters.verdict:
        v = filters.verdict.strip().lower()
        if v not in _VALID_VERDICT_FILTERS:
            raise ValueError(f"invalid verdict: {filters.verdict!r}")
        verdict = v

    return FindingsListFilters(
        org_id=filters.org_id,
        asset_ids=list(filters.asset_ids) if filters.asset_ids else [],
        severity=severity,
        scanner=scanner,
        state=state,
        q=q,
        cve=cve,
        repo=repo,
        sort=sort,
        direction=direction,
        limit=limit,
        cursor=filters.cursor,
        archived=filters.archived,
        first_seen_after=first_seen_after,
        cwe=cwe,
        kev=kev,
        epss_min=epss_min,
        risk_score_min=risk_score_min,
        assignee_user_id=assignee_user_id,
        page=page,
        verdict=verdict,
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
    if sort == "severity_age":
        from sqlalchemy import case
        rank_expr = case(
            (func.lower(Finding.severity) == "critical", 4),
            (func.lower(Finding.severity) == "high", 3),
            (func.lower(Finding.severity) == "medium", 2),
            (func.lower(Finding.severity) == "low", 1),
            else_=0,
        )
        return [
            rank_expr.desc() if desc else rank_expr.asc(),
            Finding.first_seen_at.desc() if desc else Finding.first_seen_at.asc(),
            Finding.id.desc() if desc else Finding.id.asc(),
        ]
    if sort == "newest":
        return [Finding.first_seen_at.desc(), Finding.id.desc()]
    if sort == "oldest":
        return [Finding.first_seen_at.asc(), Finding.id.asc()]
    if sort == "risk_score":
        # NULLs land at the end regardless of direction so unscored rows don't
        # crowd the top of a "Risk score (high to low)" view.
        primary = (
            Finding.risk_score.desc().nullslast()
            if desc
            else Finding.risk_score.asc().nullslast()
        )
        return [primary, Finding.id.desc() if desc else Finding.id.asc()]
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
    # Prefer asset-scoped filter; without asset_ids, return no results (fail-closed).
    if filters.asset_ids:
        clauses: list = [Finding.asset_id.in_(filters.asset_ids)]
    else:
        # Fail closed when no asset scope is provided.
        clauses = [sa_false()]
    if filters.severity:
        clauses.append(func.lower(Finding.severity).in_(filters.severity))
    if filters.verdict is None:
        clauses.append(
            or_(Finding.verdict.is_(None), Finding.verdict != "ruled_out")
        )
    elif filters.verdict == "legacy":
        clauses.append(Finding.verdict.is_(None))
    elif filters.verdict in VALID_VERDICTS:
        clauses.append(Finding.verdict == filters.verdict)
    if filters.scanner:
        internal_tools = [_PUBLIC_TO_TOOL[s] for s in filters.scanner]
        clauses.append(Finding.tool.in_(internal_tools))
    if filters.state:
        clauses.append(Finding.state.in_(filters.state))
    if filters.cve:
        cve_upper = filters.cve.upper()
        clauses.append(Finding.cve_id == cve_upper)
    if filters.repo:
        # filters.repo is the human-readable Asset.display_name (e.g. "acme/foo")
        clauses.append(
            Finding.asset_id.in_(
                select(Asset.id).where(Asset.display_name == filters.repo)
            )
        )
    if filters.first_seen_after:
        clauses.append(Finding.first_seen_at >= filters.first_seen_after)
    if filters.q:
        like = f"%{filters.q}%"
        clauses.append(
            or_(
                Finding.identity_key.ilike(like),
                Finding.title.ilike(like),
                Finding.rule_name.ilike(like),
                Finding.package_name.ilike(like),
                Finding.file_path.ilike(like),
                Finding.cve_id.ilike(like),
            )
        )

    if filters.kev is True:
        kev_subq = select(KevEntry.cve_id)
        clauses.append(Finding.cve_id.in_(kev_subq))

    if filters.cwe:
        # JSONB array containment: KevEntry.cwes @> [filters.cwe]
        cwe_subq = select(KevEntry.cve_id).where(KevEntry.cwes.contains([filters.cwe]))
        clauses.append(Finding.cve_id.in_(cwe_subq))

    if filters.risk_score_min is not None:
        clauses.append(Finding.risk_score >= filters.risk_score_min)

    if filters.assignee_user_id:
        clauses.append(Finding.assignee_user_id == filters.assignee_user_id)

    return clauses


class _KevLookup(Protocol):
    def is_kev(self, cve: str | None) -> bool: ...
    def first_cwe(self, cve: str | None) -> str | None: ...


class _NoKev:
    """No-KEV lookup — used when a query doesn't preload KEV state. Returns all-false."""
    def is_kev(self, cve: str | None) -> bool:
        return False
    def first_cwe(self, cve: str | None) -> str | None:
        return None


def _finding_to_dict(finding: Finding, kev_lookup: _KevLookup | None = None) -> dict[str, Any]:
    """Serialise a Finding to the public response shape (now including kev + cwe)."""
    lookup = kev_lookup or _NoKev()
    detail: dict = finding.detail or {}

    title = finding.title or finding.identity_key

    package = None
    pkg_name = finding.package_name
    pkg_version = detail.get("package_version") or detail.get("current_version")
    if pkg_name:
        package = f"{pkg_name}@{pkg_version}" if pkg_version else pkg_name

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
        "cve": finding.cve_id,
        "package": package,
        "file_path": finding.file_path,
        "line": line,
        "repo": finding.repo,
        "org_id": finding.org,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
        "kev": lookup.is_kev(finding.cve_id),
        "cwe": lookup.first_cwe(finding.cve_id),
        "risk_score": finding.risk_score,
        "assignee_user_id": finding.assignee_user_id,
        "verdict": finding.verdict,
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

    def _apply_archived_filter(stmt, archived: bool | None):
        if archived is True:
            return only_archived(stmt, Finding)
        return exclude_archived(stmt, Finding)

    count_stmt = select(func.count()).select_from(Finding).where(base_where)
    if filters.epss_min is not None:
        from src.db.models import EpssScore
        count_stmt = (
            count_stmt
            .join(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(EpssScore.percentile >= filters.epss_min)
        )
    count_stmt = _apply_archived_filter(count_stmt, filters.archived)
    count_result = await session.execute(count_stmt)
    total = int(count_result.scalar() or 0)

    page_where = base_where
    if cursor_clause is not None:
        page_where = and_(base_where, cursor_clause)

    epss_join_needed = filters.epss_min is not None

    offset = (filters.page - 1) * filters.limit if not filters.cursor else 0

    if filters.sort == "epss":
        from src.db.models import EpssScore
        page_stmt = (
            select(Finding)
            .outerjoin(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(page_where)
            .order_by(
                EpssScore.percentile.desc().nullslast() if filters.direction == "desc" else EpssScore.percentile.asc().nullsfirst(),
                Finding.id.desc(),
            )
            .offset(offset)
            .limit(filters.limit + 1)
        )
        if filters.epss_min is not None:
            page_stmt = page_stmt.where(EpssScore.percentile >= filters.epss_min)
    elif epss_join_needed:
        from src.db.models import EpssScore
        page_stmt = (
            select(Finding)
            .join(EpssScore, EpssScore.cve == Finding.cve_id)
            .where(page_where)
            .where(EpssScore.percentile >= filters.epss_min)
            .order_by(*_sort_columns(filters.sort, filters.direction))
            .offset(offset)
            .limit(filters.limit + 1)
        )
    else:
        page_stmt = (
            select(Finding)
            .where(page_where)
            .order_by(*_sort_columns(filters.sort, filters.direction))
            .offset(offset)
            .limit(filters.limit + 1)
        )
    page_stmt = _apply_archived_filter(page_stmt, filters.archived)
    page_result = await session.execute(page_stmt)
    rows = list(page_result.scalars().all())

    has_more = len(rows) > filters.limit
    page = rows[: filters.limit]
    next_cursor = _build_next_cursor(page[-1], filters.sort) if has_more and page else None
    if filters.sort in ("severity_age", "epss", "risk_score", "newest", "oldest"):
        next_cursor = None  # cursor pagination for these sorts is deferred to PR 5 (page-number pagination)
    if not filters.cursor:
        next_cursor = None

    cve_ids = [f.cve_id for f in page if f.cve_id]
    kev_set: set[str] = set()
    kev_cwes: dict[str, list[str]] = {}
    if cve_ids:
        kev_result = await session.execute(
            select(KevEntry.cve_id, KevEntry.cwes).where(KevEntry.cve_id.in_(cve_ids))
        )
        for cve, cwes in kev_result.all():
            kev_set.add(cve)
            if isinstance(cwes, list) and cwes:
                kev_cwes[cve] = [str(c) for c in cwes]

    class _RealKev:
        def is_kev(self, cve):
            return bool(cve) and cve in kev_set
        def first_cwe(self, cve):
            if not cve:
                return None
            cwes = kev_cwes.get(cve)
            return cwes[0] if cwes else None

    lookup = _RealKev()

    verdict_counts = await _verdict_counts_for_filters(filters, session)

    return {
        "findings": [_finding_to_dict(f, kev_lookup=lookup) for f in page],
        "next_cursor": next_cursor,
        "total_count": total,
        "verdict_counts": verdict_counts,
    }


async def _verdict_counts_for_filters(
    filters: FindingsListFilters,
    session: AsyncSession,
) -> dict[str, int]:
    """Per-verdict counts for the filter set, with the verdict filter itself disabled.

    Keeps chip counts stable as the user toggles between verdicts.
    """
    counts_filters = FindingsListFilters(**{**filters.__dict__, "verdict": "all"})
    where = _build_where_clauses(counts_filters)
    base_where = and_(*where)

    stmt = (
        select(Finding.verdict, func.count())
        .where(base_where)
        .group_by(Finding.verdict)
    )
    stmt = exclude_archived(stmt, Finding) if filters.archived is not True else only_archived(stmt, Finding)
    rows = await session.execute(stmt)

    out = {
        "total": 0,
        "confirmed": 0,
        "needs_verify": 0,
        "possible": 0,
        "ruled_out": 0,
        "legacy": 0,
    }
    for verdict, n in rows.all():
        n_int = int(n or 0)
        out["total"] += n_int
        if verdict is None:
            out["legacy"] += n_int
        elif verdict in out:
            out[verdict] += n_int
    return out


# Number of days the "fixed this week" bucket looks back. Matches the mock's
# "Resolved this week" KPI.
FIXED_WINDOW_DAYS = 7


async def summarize_findings(
    session: AsyncSession,
    *,
    asset_ids: list[str] | None = None,
    org_id: str | None = None,
) -> dict[str, int]:
    """Return cross-scanner KPI counts for the findings page.

    All buckets exclude archived rows. `open_*` counts include only rows in
    state=open; `fixed_recent` counts rows in state=fixed with fixed_at within
    the trailing FIXED_WINDOW_DAYS window; `dismissed` is all non-archived rows
    in state=dismissed regardless of age.

    Callers must supply either asset_ids (preferred, asset-scoped path) or
    org_id (legacy org-scoped path). asset_ids takes precedence.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=FIXED_WINDOW_DAYS)
    sev = func.lower(Finding.severity)
    state = func.lower(Finding.state)

    stmt = select(
        func.count().filter(state == "open").label("open"),
        func.count().filter(and_(state == "open", sev == "critical")).label("critical"),
        func.count().filter(and_(state == "open", sev == "high")).label("high"),
        func.count().filter(and_(state == "open", sev == "medium")).label("medium"),
        func.count().filter(and_(state == "open", sev == "low")).label("low"),
        func.count()
        .filter(and_(state == "fixed", Finding.fixed_at.is_not(None), Finding.fixed_at >= cutoff))
        .label("fixed_recent"),
        func.count().filter(state == "dismissed").label("dismissed"),
    )
    if asset_ids:
        stmt = stmt.where(Finding.asset_id.in_(asset_ids))
    elif org_id:
        # Fail closed when no asset scope is provided.
        stmt = stmt.where(sa_false())
    else:
        raise ValueError("summarize_findings requires asset_ids or org_id")
    stmt = exclude_archived(stmt, Finding)

    row = (await session.execute(stmt)).one()
    return {
        "open": int(row.open or 0),
        "critical": int(row.critical or 0),
        "high": int(row.high or 0),
        "medium": int(row.medium or 0),
        "low": int(row.low or 0),
        "fixed_recent": int(row.fixed_recent or 0),
        "dismissed": int(row.dismissed or 0),
        "fixed_window_days": FIXED_WINDOW_DAYS,
    }


async def assign_finding(
    finding_id: int,
    assignee_user_id: str | None,
    session: AsyncSession,
    asset_ids: list[str],
) -> tuple[Finding, str | None]:
    """Set or clear the assignee on a finding.

    Returns (finding, previous_assignee). Raises LookupError if the finding
    does not exist or its asset is outside the caller's scope (404 path —
    avoids leaking existence). Raises ValueError if assignee_user_id is
    non-empty but references a user that does not exist.
    """
    if assignee_user_id is not None:
        normalized = assignee_user_id.strip()
        if len(normalized) > 255:
            raise ValueError("assignee_user_id exceeds 255 characters")
        assignee_user_id = normalized or None

    finding = (
        await session.execute(select(Finding).where(Finding.id == finding_id))
    ).scalars().first()
    # Secrets findings (asset_id=NULL) have no per-source isolation and are
    # not surfaced through the asset-scoped /findings list, so they are out
    # of scope for assignment too.
    if (
        finding is None
        or not finding.asset_id
        or finding.asset_id not in asset_ids
    ):
        raise LookupError(f"finding {finding_id} not found")

    if assignee_user_id is not None:
        user_id = (
            await session.execute(select(User.id).where(User.id == assignee_user_id))
        ).scalar_one_or_none()
        if user_id is None:
            raise ValueError(f"unknown user: {assignee_user_id}")

    previous = finding.assignee_user_id
    finding.assignee_user_id = assignee_user_id
    finding.updated_at = datetime.now(timezone.utc)
    await session.flush()
    return finding, previous


MAX_ASSIGNABLE_USERS_LIMIT = 50


async def list_assignable_users(
    session: AsyncSession,
    *,
    q: str | None = None,
    limit: int = 20,
) -> list[dict[str, str]]:
    """Return up to `limit` active users matching `q` on username or email.

    Trims and lowers `q` before the LIKE pattern build so the caller can pass
    raw input without normalising. Empty/whitespace queries return the first
    `limit` users by username order.
    """
    capped_limit = max(1, min(int(limit or 20), MAX_ASSIGNABLE_USERS_LIMIT))
    stmt = select(User.id, User.username, User.email).where(User.status == "active")
    if q:
        normalized = q.strip()
        if normalized:
            like = f"%{normalized}%"
            stmt = stmt.where(or_(User.username.ilike(like), User.email.ilike(like)))
    stmt = stmt.order_by(User.username.asc()).limit(capped_limit)

    rows = (await session.execute(stmt)).all()
    return [
        {"id": row.id, "username": row.username, "email": row.email or ""}
        for row in rows
    ]
