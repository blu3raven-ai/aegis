"""Global search service — Phase 28.

Aggregates findings, chains, repos, audit events, and notification
destinations using Postgres ILIKE for simple substring matching.
Results are ranked: exact-match > prefix > substring.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import (
    AuditEvent,
    Chain,
    Finding,
    NotificationDestination,
    ScanRun,
)


@dataclass
class SearchHit:
    type: str
    id: str
    title: str
    subtitle: str | None
    href: str
    score: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchResults:
    query: str
    total: int
    grouped: dict[str, list[SearchHit]]
    duration_ms: int


# Scope names understood by the endpoint.
VALID_SCOPES = frozenset(
    {"findings", "chains", "repos", "audit_events", "destinations"}
)

_DEFAULT_LIMIT = 50


def _score(value: str | None, query: str) -> float:
    """Return a simple ranking score — exact > prefix > substring > 0."""
    if not value:
        return 0.0
    v = value.lower()
    q = query.lower()
    if v == q:
        return 1.0
    if v.startswith(q):
        return 0.7
    if q in v:
        return 0.4
    return 0.0


class SearchService:
    def search(
        self,
        query: str,
        *,
        scopes: list[str] | None = None,
        org_id: str | None = None,
        limit: int = _DEFAULT_LIMIT,
    ) -> SearchResults:
        """Execute a global search and return grouped, ranked results."""
        t0 = time.monotonic()

        active_scopes = (
            {s for s in scopes if s in VALID_SCOPES}
            if scopes
            else VALID_SCOPES
        )
        limit = max(1, min(limit, 200))

        grouped: dict[str, list[SearchHit]] = {}

        if "findings" in active_scopes:
            hits = self._search_findings(query, org_id=org_id, limit=limit)
            if hits:
                grouped["findings"] = hits

        if "chains" in active_scopes:
            hits = self._search_chains(query, org_id=org_id, limit=limit)
            if hits:
                grouped["chains"] = hits

        if "repos" in active_scopes:
            hits = self._search_repos(query, org_id=org_id, limit=limit)
            if hits:
                grouped["repos"] = hits

        if "audit_events" in active_scopes:
            hits = self._search_audit_events(query, org_id=org_id, limit=limit)
            if hits:
                grouped["audit_events"] = hits

        if "destinations" in active_scopes:
            hits = self._search_destinations(query, org_id=org_id, limit=limit)
            if hits:
                grouped["destinations"] = hits

        total = sum(len(v) for v in grouped.values())
        duration_ms = int((time.monotonic() - t0) * 1000)
        return SearchResults(
            query=query,
            total=total,
            grouped=grouped,
            duration_ms=duration_ms,
        )

    # ── per-scope helpers ────────────────────────────────────────────────────

    def _search_findings(
        self, query: str, *, org_id: str | None, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(Finding).where(
                or_(
                    Finding.identity_key.ilike(pat),
                    Finding.repo.ilike(pat),
                    Finding.org.ilike(pat),
                )
            )
            if org_id:
                stmt = stmt.where(Finding.org == org_id)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return result.scalars().all()

        rows = run_db(_q)
        hits: list[SearchHit] = []
        for r in rows:
            title = r.identity_key or str(r.id)
            # Score against the most descriptive searchable field
            score = max(
                _score(r.identity_key, query),
                _score(r.repo, query),
                _score(r.org, query),
            )
            hits.append(
                SearchHit(
                    type="finding",
                    id=str(r.id),
                    title=title,
                    subtitle=f"{r.repo} · {r.severity or 'unknown'}" if r.repo else r.org,
                    href=f"/{r.tool}/dashboard",
                    score=score,
                    metadata={
                        "tool": r.tool,
                        "org": r.org,
                        "repo": r.repo,
                        "severity": r.severity,
                        "state": r.state,
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    def _search_chains(
        self, query: str, *, org_id: str | None, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(Chain).where(
                or_(
                    Chain.id.ilike(pat),
                    Chain.chain_type.ilike(pat),
                )
            )
            if org_id:
                stmt = stmt.where(Chain.org_id == org_id)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return result.scalars().all()

        rows = run_db(_q)
        hits: list[SearchHit] = []
        for r in rows:
            score = max(_score(r.id, query), _score(r.chain_type, query))
            hits.append(
                SearchHit(
                    type="chain",
                    id=r.id,
                    title=r.chain_type,
                    subtitle=f"{r.severity} · {r.status}",
                    href=f"/dependencies/dashboard?chain={r.id}",
                    score=score,
                    metadata={
                        "org_id": r.org_id,
                        "severity": r.severity,
                        "status": r.status,
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    def _search_repos(
        self, query: str, *, org_id: str | None, limit: int
    ) -> list[SearchHit]:
        """Search scan runs as repo proxies — scan_runs.org / metadata source_url."""
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(ScanRun).where(
                ScanRun.org.ilike(pat)
            )
            if org_id:
                stmt = stmt.where(ScanRun.org == org_id)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return result.scalars().all()

        rows = run_db(_q)
        seen: set[str] = set()
        hits: list[SearchHit] = []
        for r in rows:
            key = r.org
            if key in seen:
                continue
            seen.add(key)
            score = _score(r.org, query)
            source_url = (r.metadata_json or {}).get("source_url")
            hits.append(
                SearchHit(
                    type="repo",
                    id=r.org,
                    title=r.org,
                    subtitle=source_url,
                    href=f"/sources/code-repositories",
                    score=score,
                    metadata={"source_url": source_url},
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    def _search_audit_events(
        self, query: str, *, org_id: str | None, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(AuditEvent).where(
                or_(
                    AuditEvent.action.ilike(pat),
                    AuditEvent.resource_id.ilike(pat),
                    AuditEvent.resource_type.ilike(pat),
                )
            )
            if org_id:
                stmt = stmt.where(AuditEvent.org_id == org_id)
            stmt = stmt.order_by(AuditEvent.occurred_at.desc().nullslast()).limit(limit)
            result = await session.execute(stmt)
            return result.scalars().all()

        rows = run_db(_q)
        hits: list[SearchHit] = []
        for r in rows:
            score = max(
                _score(r.action, query),
                _score(r.resource_id, query),
                _score(r.resource_type, query),
            )
            occurred = (
                r.occurred_at.strftime("%d %b %Y %H:%M") if r.occurred_at else None
            )
            hits.append(
                SearchHit(
                    type="audit_event",
                    id=str(r.id),
                    title=r.action,
                    subtitle=occurred,
                    href="/settings/audit",
                    score=score,
                    metadata={
                        "resource_type": r.resource_type,
                        "resource_id": r.resource_id,
                        "actor": r.actor_username or r.actor_user_id,
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    def _search_destinations(
        self, query: str, *, org_id: str | None, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(NotificationDestination).where(
                or_(
                    NotificationDestination.name.ilike(pat),
                    NotificationDestination.destination_type.ilike(pat),
                )
            )
            if org_id:
                stmt = stmt.where(NotificationDestination.org_id == org_id)
            stmt = stmt.limit(limit)
            result = await session.execute(stmt)
            return result.scalars().all()

        rows = run_db(_q)
        hits: list[SearchHit] = []
        for r in rows:
            score = max(
                _score(r.name, query),
                _score(r.destination_type, query),
            )
            hits.append(
                SearchHit(
                    type="destination",
                    id=str(r.id),
                    title=r.name,
                    subtitle=r.destination_type,
                    href="/settings/notifications",
                    score=score,
                    metadata={
                        "destination_type": r.destination_type,
                        "enabled": r.enabled,
                        "org_id": r.org_id,
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits
