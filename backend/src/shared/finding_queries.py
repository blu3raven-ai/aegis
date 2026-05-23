"""Shared finding CRUD helpers and analytics queries.

All functions that accept a session parameter are async coroutines meant
to be called inside run_db().  Functions that do NOT accept a session are
pure helpers that transform data in memory.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Decision, Finding, FindingEvent


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

async def read_findings(
    session: AsyncSession,
    tool: str,
    org: str,
) -> list[Finding]:
    """Load all findings for a tool+org."""
    result = await session.execute(
        select(Finding).where(Finding.tool == tool, Finding.org == org)
    )
    return list(result.scalars().all())


async def upsert_finding(
    session: AsyncSession,
    *,
    tool: str,
    org: str,
    repo: str | None,
    identity_key: str,
    state: str,
    severity: str | None,
    detail: dict,
    first_seen_at: datetime | None = None,
    fixed_at: datetime | None = None,
) -> Finding:
    """Insert or update a finding by (tool, org, identity_key)."""
    now = _utcnow()
    result = await session.execute(
        select(Finding).where(
            Finding.tool == tool,
            Finding.org == org,
            Finding.identity_key == identity_key,
        )
    )
    existing = result.scalars().first()
    if existing:
        existing.state = state
        existing.severity = severity
        existing.repo = repo
        existing.detail = detail
        existing.last_seen_at = now
        existing.updated_at = now
        if fixed_at is not None:
            existing.fixed_at = fixed_at
        elif state != "fixed":
            existing.fixed_at = None
        return existing
    else:
        finding = Finding(
            tool=tool,
            org=org,
            repo=repo,
            identity_key=identity_key,
            state=state,
            severity=severity,
            detail=detail,
            first_seen_at=first_seen_at or now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
        )
        session.add(finding)
        await session.flush()
        return finding


async def update_finding_state(
    session: AsyncSession,
    finding: Finding,
    new_state: str,
    fixed_at: datetime | None = None,
) -> None:
    """Update a finding's state and timestamp."""
    finding.state = new_state
    finding.updated_at = _utcnow()
    if new_state == "fixed":
        finding.fixed_at = fixed_at or _utcnow()
    else:
        finding.fixed_at = None


# ---------------------------------------------------------------------------
# Decision CRUD
# ---------------------------------------------------------------------------

async def read_decisions_for_org(
    session: AsyncSession,
    tool: str,
    org: str,
) -> dict[str, Decision]:
    """Load all decisions for a tool+org, keyed by identity_key."""
    result = await session.execute(
        select(Decision).where(Decision.tool == tool, Decision.org == org)
    )
    return {d.identity_key: d for d in result.scalars().all()}


async def upsert_decision(
    session: AsyncSession,
    *,
    tool: str,
    org: str,
    identity_key: str,
    status: str,
    reason: str | None = None,
    comment: str | None = None,
    decided_by: str | None = None,
) -> Decision:
    """Insert or update a decision."""
    now = _utcnow()
    result = await session.execute(
        select(Decision).where(
            Decision.tool == tool,
            Decision.org == org,
            Decision.identity_key == identity_key,
        )
    )
    existing = result.scalars().first()
    if existing:
        existing.status = status
        existing.reason = reason
        existing.comment = comment
        existing.decided_by = decided_by
        existing.decided_at = now
        return existing
    else:
        decision = Decision(
            tool=tool,
            org=org,
            identity_key=identity_key,
            status=status,
            reason=reason,
            comment=comment,
            decided_by=decided_by,
            decided_at=now,
            created_at=now,
        )
        session.add(decision)
        return decision


async def delete_decision(
    session: AsyncSession,
    tool: str,
    org: str,
    identity_key: str,
) -> bool:
    """Delete a decision (used for reopen). Returns True if a row was deleted."""
    result = await session.execute(
        delete(Decision).where(
            Decision.tool == tool,
            Decision.org == org,
            Decision.identity_key == identity_key,
        )
    )
    return result.rowcount > 0


# ---------------------------------------------------------------------------
# Event logging
# ---------------------------------------------------------------------------

async def insert_event(
    session: AsyncSession,
    *,
    finding_id: int,
    tool: str,
    org: str,
    identity_key: str,
    from_state: str | None,
    to_state: str,
    triggered_by: str,
    actor: str | None = None,
    metadata: dict | None = None,
) -> None:
    """Append an audit event."""
    session.add(FindingEvent(
        finding_id=finding_id,
        tool=tool,
        org=org,
        identity_key=identity_key,
        from_state=from_state,
        to_state=to_state,
        triggered_by=triggered_by,
        actor=actor,
        metadata_json=metadata or {},
        created_at=_utcnow(),
    ))


# ---------------------------------------------------------------------------
# Secrets review status
# ---------------------------------------------------------------------------

def set_secret_review_status(org: str, identity_key: str, review_status: str | None) -> None:
    from src.db.helpers import run_db
    from src.shared.paths import normalize_org

    async def _run(session: AsyncSession) -> None:
        result = await session.execute(
            select(Finding).where(
                Finding.tool == "secrets",
                Finding.org == normalize_org(org),
                Finding.identity_key == identity_key,
            )
        )
        finding = result.scalars().first()
        if finding:
            finding.review_status = review_status
            finding.updated_at = _utcnow()

    run_db(_run)


# ---------------------------------------------------------------------------
# Analytics (pure functions operating on query results)
# ---------------------------------------------------------------------------

def compute_severity_counts(rows: list[tuple[str, int]]) -> dict[str, int]:
    """Convert [(severity, count), ...] rows into a counts dict."""
    counts = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    for severity, count in rows:
        if severity in counts:
            counts[severity] = count
        counts["total"] += count
    return counts


async def query_severity_counts(
    session: AsyncSession,
    tool: str,
    org: str,
    active_states: tuple[str, ...] = ("open", "deferred"),
) -> dict[str, int]:
    """Query severity counts for active findings."""
    result = await session.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.tool == tool,
            Finding.org == org,
            Finding.state.in_(active_states),
        )
        .group_by(Finding.severity)
    )
    return compute_severity_counts(list(result.all()))


async def query_top_repositories(
    session: AsyncSession,
    tool: str,
    org: str,
    limit: int = 10,
    active_states: tuple[str, ...] = ("open", "deferred"),
) -> list[dict[str, Any]]:
    """Query top repositories by open finding count with severity breakdown."""
    result = await session.execute(
        select(
            Finding.repo,
            func.count().label("open"),
            func.count().filter(Finding.severity == "critical").label("critical"),
            func.count().filter(Finding.severity == "high").label("high"),
        )
        .where(
            Finding.tool == tool,
            Finding.org == org,
            Finding.state.in_(active_states),
            Finding.repo.isnot(None),
        )
        .group_by(Finding.repo)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [
        {"name": row.repo, "open": row.open, "critical": row.critical, "high": row.high}
        for row in result.all()
    ]
