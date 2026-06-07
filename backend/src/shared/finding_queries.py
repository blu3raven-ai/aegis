"""Shared finding CRUD helpers and analytics queries.

All functions that accept a session parameter are async coroutines meant
to be called inside run_db().  Functions that do NOT accept a session are
pure helpers that transform data in memory.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Decision, Finding, FindingEvent
from src.shared.finding_detail_blob import (
    split_detail,
    put_detail_blob,
    delete_detail_blob,
)
from src.shared.finding_queryable_fields import extract_queryable_fields


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Finding CRUD
# ---------------------------------------------------------------------------

async def read_findings(
    session: AsyncSession,
    *,
    tool: str,
    asset_ids: list[str],
) -> list[Finding]:
    """Load all findings for a tool scoped to the given asset IDs."""
    if not asset_ids:
        return []
    result = await session.execute(
        select(Finding).where(
            Finding.tool == tool,
            Finding.asset_id.in_(asset_ids),
        )
    )
    return list(result.scalars().all())


async def read_dependency_finding_detail_by_key(
    session: AsyncSession,
    *,
    asset_ids: list[str],
    identity_key: str,
) -> "tuple[Finding, Decision | None, Asset] | None":
    """Fetch a single dependencies finding with its decision and asset row."""
    if not asset_ids:
        return None
    result = await session.execute(
        select(Finding, Decision, Asset)
        .outerjoin(
            Decision,
            and_(
                Decision.tool == Finding.tool,
                Decision.asset_id == Finding.asset_id,
                Decision.identity_key == Finding.identity_key,
            ),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .where(
            Finding.tool == "dependencies",
            Finding.asset_id.in_(asset_ids),
            Finding.identity_key == identity_key,
        )
    )
    row = result.first()
    return row if row else None


async def upsert_finding(
    session: AsyncSession,
    *,
    tool: str,
    asset_id: str | None,
    org: str = "",  # kept for compat; not written to DB after Plan D
    repo: str | None = None,  # kept for compat; not written to DB after Plan D
    identity_key: str,
    state: str,
    severity: str | None,
    detail: dict,
    first_seen_at: datetime | None = None,
    fixed_at: datetime | None = None,
    engine: str | None = None,
    introduced_by_commit_sha: str | None = None,
    introduced_by_author: str | None = None,
    introduced_at: datetime | None = None,
    introduced_by_pr_url: str | None = None,
) -> Finding:
    """Insert or update a finding by (tool, asset_id, identity_key).

    Secrets findings have asset_id=NULL and are matched by (tool, identity_key) only.
    Attribution fields are only set on insert (the introducing commit doesn't
    change when a finding resurfaces). Callers may omit them; they default to
    NULL, which is valid and indicates attribution was unavailable at ingest.
    """
    now = _utcnow()
    if asset_id is not None:
        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.asset_id == asset_id,
                Finding.identity_key == identity_key,
            )
        )
    else:
        # Secrets: match by tool + identity_key (asset_id is NULL)
        result = await session.execute(
            select(Finding).where(
                Finding.tool == tool,
                Finding.asset_id.is_(None),
                Finding.identity_key == identity_key,
            )
        )
    existing = result.scalars().first()

    # Extract typed-column values from full detail BEFORE split runs.
    queryable = extract_queryable_fields(detail)

    if existing:
        lean, fat = split_detail(tool, detail)
        existing.state = state
        existing.severity = severity
        existing.asset_id = asset_id
        existing.detail = lean
        existing.cve_id = queryable["cve_id"]
        existing.file_path = queryable["file_path"]
        existing.title = queryable["title"]
        existing.rule_name = queryable["rule_name"]
        existing.package_name = queryable["package_name"]
        if engine is not None:
            existing.engine = engine
        existing.last_seen_at = now
        existing.updated_at = now
        if fixed_at is not None:
            existing.fixed_at = fixed_at
        elif state != "fixed":
            existing.fixed_at = None
        if fat:
            existing.detail_blob_key = put_detail_blob(existing.id, fat)
        elif existing.detail_blob_key:
            delete_detail_blob(existing.detail_blob_key)
            existing.detail_blob_key = None
        return existing
    else:
        lean, fat = split_detail(tool, detail)
        finding = Finding(
            tool=tool,
            asset_id=asset_id,
            identity_key=identity_key,
            state=state,
            severity=severity,
            detail=lean,
            cve_id=queryable["cve_id"],
            file_path=queryable["file_path"],
            title=queryable["title"],
            rule_name=queryable["rule_name"],
            package_name=queryable["package_name"],
            engine=engine,
            first_seen_at=first_seen_at or now,
            last_seen_at=now,
            created_at=now,
            updated_at=now,
            introduced_by_commit_sha=introduced_by_commit_sha,
            introduced_by_author=introduced_by_author,
            introduced_at=introduced_at,
            introduced_by_pr_url=introduced_by_pr_url,
        )
        session.add(finding)
        await session.flush()
        if fat:
            finding.detail_blob_key = put_detail_blob(finding.id, fat)

        # Pre-seed the hydrated detail cache so apply_finding_mappings sees the
        # full detail (lean + fat) without a MinIO round-trip. The full dict is
        # already in memory; there is no need to download the blob we just uploaded.
        finding._hydrated_detail = dict(detail)

        # Derive and persist compliance mappings for the new finding.
        # Runs inside the same session/transaction so no extra round-trip.
        try:
            from src.compliance.auto_mapper import apply_finding_mappings
            await apply_finding_mappings(session, finding)
        except Exception:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "compliance auto-mapping failed for finding %d; skipping",
                finding.id, exc_info=True,
            )

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

async def read_decisions_for_asset(
    session: AsyncSession,
    tool: str,
    asset_id: str | None,
) -> dict[str, Decision]:
    """Load all decisions for a tool+asset, keyed by identity_key.

    asset_id=None covers secrets decisions (which have NULL asset_id).
    """
    if asset_id is not None:
        result = await session.execute(
            select(Decision).where(
                Decision.tool == tool,
                Decision.asset_id == asset_id,
            )
        )
    else:
        result = await session.execute(
            select(Decision).where(
                Decision.tool == tool,
                Decision.asset_id.is_(None),
            )
        )
    return {d.identity_key: d for d in result.scalars().all()}


async def upsert_decision(
    session: AsyncSession,
    *,
    tool: str,
    org: str = "",  # kept for compat; not written to DB after Plan D
    asset_id: str | None = None,
    identity_key: str,
    status: str,
    reason: str | None = None,
    comment: str | None = None,
    decided_by: str | None = None,
) -> Decision:
    """Insert or update a decision keyed by (tool, asset_id, identity_key)."""
    now = _utcnow()
    if asset_id is not None:
        result = await session.execute(
            select(Decision).where(
                Decision.tool == tool,
                Decision.asset_id == asset_id,
                Decision.identity_key == identity_key,
            )
        )
    else:
        result = await session.execute(
            select(Decision).where(
                Decision.tool == tool,
                Decision.asset_id.is_(None),
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
            asset_id=asset_id,
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
    org: str = "",  # kept for compat; not used after Plan D
    identity_key: str = "",
    asset_id: str | None = None,
) -> bool:
    """Delete a decision (used for reopen). Returns True if a row was deleted."""
    if asset_id is not None:
        result = await session.execute(
            delete(Decision).where(
                Decision.tool == tool,
                Decision.asset_id == asset_id,
                Decision.identity_key == identity_key,
            )
        )
    else:
        result = await session.execute(
            delete(Decision).where(
                Decision.tool == tool,
                Decision.asset_id.is_(None),
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
    # Secrets have asset_id=NULL by design (they're scanner-emitted but don't
    # bind to a specific repo asset). Match by (tool, identity_key) only.
    # Multi-tenant isolation for secrets is intentionally deferred until a
    # per-secret-source identity model is needed.
    from src.db.helpers import run_db

    async def _run(session: AsyncSession) -> None:
        result = await session.execute(
            select(Finding).where(
                Finding.tool == "secrets",
                Finding.asset_id.is_(None),
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
    *,
    tool: str,
    asset_ids: list[str],
    active_states: tuple[str, ...] = ("open", "deferred"),
) -> dict[str, int]:
    """Query severity counts for active findings scoped to the given asset IDs."""
    if not asset_ids:
        return compute_severity_counts([])
    result = await session.execute(
        select(Finding.severity, func.count())
        .where(
            Finding.tool == tool,
            Finding.asset_id.in_(asset_ids),
            Finding.state.in_(active_states),
        )
        .group_by(Finding.severity)
    )
    return compute_severity_counts(list(result.all()))


async def query_top_repositories(
    session: AsyncSession,
    *,
    tool: str,
    asset_ids: list[str],
    limit: int = 10,
    active_states: tuple[str, ...] = ("open", "deferred"),
) -> list[dict[str, Any]]:
    """Query top assets (repos) by open finding count with severity breakdown."""
    if not asset_ids:
        return []
    result = await session.execute(
        select(
            Finding.asset_id,
            Asset.display_name.label("name"),
            func.count().label("open"),
            func.count().filter(Finding.severity == "critical").label("critical"),
            func.count().filter(Finding.severity == "high").label("high"),
        )
        .join(Asset, Asset.id == Finding.asset_id)
        .where(
            Finding.tool == tool,
            Finding.asset_id.in_(asset_ids),
            Finding.state.in_(active_states),
        )
        .group_by(Finding.asset_id, Asset.display_name)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [
        {"name": row.name, "open": row.open, "critical": row.critical, "high": row.high}
        for row in result.all()
    ]
