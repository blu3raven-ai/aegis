"""Global search service — Phase 28.

Aggregates findings, repos, audit events, and notification destinations
using Postgres ILIKE for simple substring matching. Results are ranked:
exact-match > prefix > substring.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import (
    Asset,
    AuditEvent,
    Finding,
    NotificationDestination,
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
    {"findings", "repos", "audit_events", "destinations"}
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
        asset_ids: list[str] | None = None,
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
            hits = self._search_findings(query, org_id=org_id, asset_ids=asset_ids, limit=limit)
            if hits:
                grouped["findings"] = hits

        if "repos" in active_scopes:
            hits = self._search_repos(query, org_id=org_id, limit=limit, asset_ids=asset_ids)
            if hits:
                grouped["repos"] = hits

        if "audit_events" in active_scopes:
            hits = self._search_audit_events(query, limit=limit)
            if hits:
                grouped["audit_events"] = hits

        if "destinations" in active_scopes:
            hits = self._search_destinations(query, limit=limit)
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
        self,
        query: str,
        *,
        org_id: str | None,
        asset_ids: list[str] | None = None,
        limit: int,
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            # Search identity_key, title, and the asset's display_name so users
            # can search "acme/foo" or "owner/repo" to find findings on that
            # repo. Joins through Asset because Finding.org/repo were dropped
            # in Plan D.
            stmt = (
                select(Finding)
                .join(Asset, Asset.id == Finding.asset_id)
                .where(
                    or_(
                        Finding.identity_key.ilike(pat),
                        Finding.title.ilike(pat),
                        Asset.display_name.ilike(pat),
                    )
                )
            )
            if asset_ids is not None:
                if not asset_ids:
                    return []
                stmt = stmt.where(Finding.asset_id.in_(asset_ids))
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
                _score(r.title or "", query),
            )
            hits.append(
                SearchHit(
                    type="finding",
                    id=str(r.id),
                    title=title,
                    subtitle=f"{r.severity or 'unknown'}",
                    href=f"/findings?scanner={r.tool}",
                    score=score,
                    metadata={
                        "tool": r.tool,
                        "severity": r.severity,
                        "state": r.state,
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits

    def _search_repos(
        self, query: str, *, org_id: str | None, limit: int,
        asset_ids: list[str] | None = None,
    ) -> list[SearchHit]:
        """Search assets (repos and images) by display_name or external_ref.

        Asset is the post-Plan-D source of truth for repo identity — ScanRun
        no longer carries org/repo strings. Scope to asset_ids when given so
        results stay within the caller's grants.
        """
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = (
                select(Asset).where(
                    or_(
                        Asset.display_name.ilike(pat),
                        Asset.external_ref.ilike(pat),
                    )
                )
            )
            if asset_ids is not None:
                if not asset_ids:
                    return []
                stmt = stmt.where(Asset.id.in_(asset_ids))
            stmt = stmt.limit(limit)
            return (await session.execute(stmt)).scalars().all()

        rows = run_db(_q)
        return [
            SearchHit(
                type="repo",
                id=str(asset.id),
                title=asset.display_name,
                subtitle=asset.external_ref,
                href=f"/findings?asset_id={asset.id}",
                score=_score(asset.display_name, query),
                metadata={"asset_type": asset.type, "source": asset.source},
            )
            for asset in rows
        ]

    def _search_audit_events(
        self, query: str, *, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = (
                select(AuditEvent)
                .where(
                    or_(
                        AuditEvent.action.ilike(pat),
                        AuditEvent.resource_id.ilike(pat),
                        AuditEvent.resource_type.ilike(pat),
                    )
                )
                .order_by(AuditEvent.occurred_at.desc().nullslast())
                .limit(limit)
            )
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
        self, query: str, *, limit: int
    ) -> list[SearchHit]:
        pat = f"%{query}%"

        async def _q(session: AsyncSession):
            stmt = select(NotificationDestination).where(
                or_(
                    NotificationDestination.name.ilike(pat),
                    NotificationDestination.destination_type.ilike(pat),
                )
            ).limit(limit)
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
                    },
                )
            )
        hits.sort(key=lambda h: h.score, reverse=True)
        return hits
