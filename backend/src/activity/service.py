"""Activity feed service — Phase 52.

Provides a unified read-side view of recent org events by aggregating
rows from several tables (findings, finding_events, scan_runs, audit_events)
into a single timeline. Cursor-based pagination uses base64-encoded
(occurred_at, id, source) tuples so callers get stable pages without
offset drift as new events land.
"""
from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, union_all, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import AuditEvent, Finding, FindingEvent, ScanRun

logger = logging.getLogger(__name__)

# ── Event type registry ───────────────────────────────────────────────────────

SUPPORTED_TYPES: list[str] = [
    "finding.created",
    "finding.dismissed",
    "finding.fixed",
    "finding.reopened",
    "scan.completed",
    "scan.failed",
    "integration.connected",
    "integration.disconnected",
    "intel.cve.added",
    "sla.breached",
    "kev.added",
]

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 200


# ── Domain model ──────────────────────────────────────────────────────────────

@dataclass
class ActivityEvent:
    id: str
    type: str
    occurred_at: datetime
    actor: str | None
    repo_id: str | None
    summary: str
    payload: dict[str, Any] = field(default_factory=dict)


# ── Cursor helpers ────────────────────────────────────────────────────────────

def _encode_cursor(occurred_at: datetime, row_id: Any, source: str) -> str:
    ts = occurred_at.isoformat() if occurred_at else ""
    raw = json.dumps({"t": ts, "i": str(row_id), "s": source})
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime | None, str | None, str | None]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        data = json.loads(raw)
        ts = datetime.fromisoformat(data["t"]) if data.get("t") else None
        return ts, data.get("i"), data.get("s")
    except Exception:
        return None, None, None


# ── Summary builders ──────────────────────────────────────────────────────────

def _finding_event_type(from_state: str | None, to_state: str) -> str:
    if to_state == "dismissed":
        return "finding.dismissed"
    if to_state == "fixed":
        return "finding.fixed"
    if to_state == "open" and from_state in ("dismissed", "fixed"):
        return "finding.reopened"
    return "finding.created"


def _finding_event_summary(evt_type: str, detail: dict[str, Any], repo: str | None) -> str:
    title = detail.get("title") or detail.get("description") or detail.get("ruleId") or "finding"
    repo_part = f" in {repo}" if repo else ""
    verbs = {
        "finding.created": "New finding",
        "finding.dismissed": "Finding dismissed",
        "finding.fixed": "Finding fixed",
        "finding.reopened": "Finding reopened",
    }
    verb = verbs.get(evt_type, "Finding updated")
    return f"{verb}: {title}{repo_part}"


def _scan_summary(tool: str, status: str, metadata: dict[str, Any] | None) -> str:
    meta = metadata or {}
    label = tool.replace("_", " ").title()
    if status == "completed":
        count = meta.get("new_findings", 0)
        if count:
            return f"{label} scan completed — {count} new finding(s)"
        return f"{label} scan completed"
    if status in ("failed", "error"):
        return f"{label} scan failed"
    if status == "cancelled":
        return f"{label} scan cancelled"
    return f"{label} scan {status}"


def _audit_event_type(action: str) -> str:
    """Map an audit action string to an activity event type."""
    if "integration" in action and "connect" in action:
        return "integration.connected"
    if "integration" in action and ("disconnect" in action or "remov" in action):
        return "integration.disconnected"
    if action in ("sla.breach", "sla.breached"):
        return "sla.breached"
    if "kev" in action and ("add" in action or "new" in action):
        return "kev.added"
    if "cve" in action and ("add" in action or "new" in action):
        return "intel.cve.added"
    return "unknown"


# ── Service ───────────────────────────────────────────────────────────────────

class ActivityService:
    def list_recent(
        self,
        org_id: str,
        *,
        types: list[str] | None = None,
        repo_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = _DEFAULT_LIMIT,
        cursor: str | None = None,
    ) -> tuple[list[ActivityEvent], str | None]:
        """Return (events, next_cursor) for the given org."""
        limit = max(1, min(limit, _MAX_LIMIT))

        # Decode cursor to determine the cutoff point for keyset pagination.
        cursor_at: datetime | None = None
        if cursor:
            cursor_at, _, _ = _decode_cursor(cursor)

        events = run_db(
            lambda session: self._query(
                session,
                org_id=org_id,
                types=types,
                repo_id=repo_id,
                since=since,
                until=until,
                limit=limit + 1,   # fetch one extra to detect next page
                cursor_at=cursor_at,
            )
        )

        has_more = len(events) > limit
        page = events[:limit]

        next_cursor: str | None = None
        if has_more and page:
            last = page[-1]
            next_cursor = _encode_cursor(last.occurred_at, last.id, "activity")

        return page, next_cursor

    # ── Internal async query ─────────────────────────────────────────────────

    async def _query(
        self,
        session: AsyncSession,
        org_id: str,
        types: list[str] | None,
        repo_id: str | None,
        since: datetime | None,
        until: datetime | None,
        limit: int,
        cursor_at: datetime | None,
    ) -> list[ActivityEvent]:
        results: list[ActivityEvent] = []

        # Determine which source tables to include based on requested types.
        want_findings = _wants(types, {"finding.created", "finding.dismissed",
                                       "finding.fixed", "finding.reopened"})
        want_scans = _wants(types, {"scan.completed", "scan.failed"})
        want_audit = _wants(types, {"integration.connected", "integration.disconnected",
                                    "sla.breached", "kev.added", "intel.cve.added"})

        if want_findings:
            results.extend(
                await self._query_finding_events(
                    session, org_id=org_id, types=types,
                    repo_id=repo_id, since=since, until=until,
                    cursor_at=cursor_at, limit=limit,
                )
            )

        if want_scans:
            results.extend(
                await self._query_scan_runs(
                    session, org_id=org_id, types=types,
                    repo_id=repo_id, since=since, until=until,
                    cursor_at=cursor_at, limit=limit,
                )
            )

        if want_audit:
            results.extend(
                await self._query_audit_events(
                    session, org_id=org_id, types=types,
                    since=since, until=until,
                    cursor_at=cursor_at, limit=limit,
                )
            )

        # Merge and sort — most recent first.
        results.sort(key=lambda e: e.occurred_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
        return results[:limit]

    async def _query_finding_events(
        self,
        session: AsyncSession,
        org_id: str,
        types: list[str] | None,
        repo_id: str | None,
        since: datetime | None,
        until: datetime | None,
        cursor_at: datetime | None,
        limit: int,
    ) -> list[ActivityEvent]:
        from src.db.models import Asset
        stmt = (
            select(FindingEvent, Finding, Asset)
            .join(Finding, FindingEvent.finding_id == Finding.id)
            .join(Asset, Asset.id == Finding.asset_id)
            .where(FindingEvent.org == org_id)
        )

        # repo_id filters on Asset.display_name (canonical "owner/repo" form for
        # repo assets). Callers pass the same display_name the UI shows.
        if repo_id:
            stmt = stmt.where(Asset.display_name == repo_id)
        if since:
            stmt = stmt.where(FindingEvent.created_at >= since)
        if until:
            stmt = stmt.where(FindingEvent.created_at <= until)
        if cursor_at:
            stmt = stmt.where(FindingEvent.created_at < cursor_at)

        stmt = stmt.order_by(FindingEvent.created_at.desc()).limit(limit)
        result = await session.execute(stmt)
        rows = result.all()

        out: list[ActivityEvent] = []
        for fe, f, asset in rows:
            evt_type = _finding_event_type(fe.from_state, fe.to_state)
            if types and evt_type not in types:
                continue
            ts = fe.created_at or datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            out.append(ActivityEvent(
                id=f"fe-{fe.id}",
                type=evt_type,
                occurred_at=ts,
                actor=fe.actor or fe.triggered_by,
                repo_id=asset.display_name if asset is not None else None,
                summary=_finding_event_summary(evt_type, f.detail or {}, None),
                payload={
                    "finding_id": f.id,
                    "tool": f.tool,
                    "severity": f.severity,
                    "identity_key": f.identity_key,
                    "from_state": fe.from_state,
                    "to_state": fe.to_state,
                    "triggered_by": fe.triggered_by,
                },
            ))
        return out

    async def _query_scan_runs(
        self,
        session: AsyncSession,
        org_id: str,
        types: list[str] | None,
        repo_id: str | None,
        since: datetime | None,
        until: datetime | None,
        cursor_at: datetime | None,
        limit: int,
    ) -> list[ActivityEvent]:
        stmt = select(ScanRun).where(
            ScanRun.metadata_json["org_label"].astext == org_id,
            ScanRun.status.in_(["completed", "failed", "error"]),
        )

        ts_col = ScanRun.finished_at
        if since:
            stmt = stmt.where(ts_col >= since)
        if until:
            stmt = stmt.where(ts_col <= until)
        if cursor_at:
            stmt = stmt.where(ts_col < cursor_at)

        stmt = stmt.order_by(ts_col.desc().nullslast()).limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        out: list[ActivityEvent] = []
        for run in rows:
            evt_type = "scan.completed" if run.status == "completed" else "scan.failed"
            if types and evt_type not in types:
                continue
            ts = run.finished_at or run.started_at or datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            meta = run.metadata_json or {}
            repo_slug = meta.get("repo") or repo_id
            out.append(ActivityEvent(
                id=f"sr-{run.id}",
                type=evt_type,
                occurred_at=ts,
                actor="system",
                repo_id=repo_slug,
                summary=_scan_summary(run.tool, run.status, meta),
                payload={
                    "run_id": run.id,
                    "tool": run.tool,
                    "status": run.status,
                    "repo": repo_slug,
                    "new_findings": meta.get("new_findings", 0),
                },
            ))
        return out

    async def _query_audit_events(
        self,
        session: AsyncSession,
        org_id: str,
        types: list[str] | None,
        since: datetime | None,
        until: datetime | None,
        cursor_at: datetime | None,
        limit: int,
    ) -> list[ActivityEvent]:
        # Only surface actions that map to a known activity type.
        relevant_actions = [
            "integration.connected",
            "integration.disconnected",
            "integration.removed",
            "sla.breach",
            "sla.breached",
            "kev.added",
            "kev.new_entries",
            "intel.cve.added",
        ]
        stmt = (
            select(AuditEvent)
            .where(
                AuditEvent.org_id == org_id,
                AuditEvent.action.in_(relevant_actions),
            )
        )

        ts_col = AuditEvent.occurred_at
        if since:
            stmt = stmt.where(ts_col >= since)
        if until:
            stmt = stmt.where(ts_col <= until)
        if cursor_at:
            stmt = stmt.where(ts_col < cursor_at)

        stmt = stmt.order_by(ts_col.desc().nullslast()).limit(limit)
        result = await session.execute(stmt)
        rows = result.scalars().all()

        out: list[ActivityEvent] = []
        for ae in rows:
            evt_type = _audit_event_type(ae.action)
            if evt_type == "unknown":
                continue
            if types and evt_type not in types:
                continue
            ts = ae.occurred_at or ae.created_at or datetime.now(timezone.utc)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            meta = ae.metadata_json or {}
            out.append(ActivityEvent(
                id=f"ae-{ae.id}",
                type=evt_type,
                occurred_at=ts,
                actor=ae.actor_email or ae.actor_username or ae.actor_user_id or "system",
                repo_id=None,
                summary=ae.target or meta.get("summary") or ae.action.replace(".", " ").title(),
                payload={
                    "audit_id": ae.id,
                    "action": ae.action,
                    "resource_type": ae.resource_type,
                    "resource_id": ae.resource_id,
                    "metadata": meta,
                },
            ))
        return out


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wants(types: list[str] | None, candidates: set[str]) -> bool:
    """Return True when no type filter is set, or when any candidate is requested."""
    if types is None:
        return True
    return bool(candidates.intersection(types))
