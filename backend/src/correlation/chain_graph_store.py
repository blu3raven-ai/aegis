"""Chain graph store — DB layer for chains and chain_edges tables.

All writes use ON CONFLICT DO NOTHING / DO UPDATE for idempotency so that
re-running the same correlation rule on the same event is safe.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import Chain, ChainEdge
from src.shared.event_types.base import _ulid

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ChainGraphStore:
    """CRUD operations on chains + chain_edges.

    All methods are synchronous wrappers over async Postgres via run_db().
    """

    # ── chains ────────────────────────────────────────────────────────────────

    def create_chain(
        self,
        *,
        org_id: str,
        chain_type: str,
        severity: str,
        status: str = "open",
    ) -> str:
        """Insert a new chain row and return its ULID id."""
        chain_id = _ulid()
        now = _utcnow()

        async def _insert(session):
            stmt = (
                pg_insert(Chain)
                .values(
                    id=chain_id,
                    org_id=org_id,
                    chain_type=chain_type,
                    severity=severity,
                    status=status,
                    created_at=now,
                    last_updated_at=now,
                )
                .on_conflict_do_nothing(index_elements=["id"])
            )
            await session.execute(stmt)

            # Derive compliance mappings for the new chain.
            try:
                from src.compliance.auto_mapper import apply_chain_mappings
                await apply_chain_mappings(session, chain_id, chain_type, severity)
            except Exception:
                logger.warning(
                    "compliance auto-mapping failed for chain %s; skipping",
                    chain_id, exc_info=True,
                )

        run_db(_insert)
        return chain_id

    def get_chain(self, chain_id: str) -> dict[str, Any] | None:
        """Return a chain as a plain dict, or None if not found."""

        async def _fetch(session):
            result = await session.execute(
                select(Chain).where(Chain.id == chain_id)
            )
            row = result.scalars().first()
            if row is None:
                return None
            return {
                "id": row.id,
                "org_id": row.org_id,
                "chain_type": row.chain_type,
                "severity": row.severity,
                "status": row.status,
                "created_at": row.created_at,
                "last_updated_at": row.last_updated_at,
                "ai_explanation_id": row.ai_explanation_id,
            }

        return run_db(_fetch)

    def find_chains_by_finding(self, finding_id: int) -> list[dict[str, Any]]:
        """Return all chains that have an edge referencing the given finding."""

        async def _fetch(session):
            result = await session.execute(
                select(Chain)
                .join(ChainEdge, ChainEdge.chain_id == Chain.id)
                .where(
                    (ChainEdge.source_finding_id == finding_id)
                    | (ChainEdge.target_finding_id == finding_id)
                )
                .distinct()
            )
            rows = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "org_id": r.org_id,
                    "chain_type": r.chain_type,
                    "severity": r.severity,
                    "status": r.status,
                    "created_at": r.created_at,
                    "last_updated_at": r.last_updated_at,
                    "ai_explanation_id": r.ai_explanation_id,
                }
                for r in rows
            ]

        return run_db(_fetch)

    def update_chain_severity(self, chain_id: str, new_severity: str) -> None:
        """Bump the severity of a chain and touch last_updated_at."""

        async def _update(session):
            await session.execute(
                update(Chain)
                .where(Chain.id == chain_id)
                .values(severity=new_severity, last_updated_at=_utcnow())
            )

        run_db(_update)

    def list_chains(
        self,
        org_id: str,
        *,
        severity: str | None = None,
        chain_type: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List chains for an org with optional filters."""

        async def _fetch(session):
            stmt = select(Chain).where(Chain.org_id == org_id)
            if severity is not None:
                stmt = stmt.where(Chain.severity == severity)
            if chain_type is not None:
                stmt = stmt.where(Chain.chain_type == chain_type)
            stmt = stmt.order_by(Chain.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "org_id": r.org_id,
                    "chain_type": r.chain_type,
                    "severity": r.severity,
                    "status": r.status,
                    "created_at": r.created_at,
                    "last_updated_at": r.last_updated_at,
                    "ai_explanation_id": r.ai_explanation_id,
                }
                for r in rows
            ]

        return run_db(_fetch)

    # ── chain_edges ───────────────────────────────────────────────────────────

    def add_edge(
        self,
        *,
        chain_id: str,
        source_finding_id: int,
        target_finding_id: int,
        edge_type: str,
        confidence: float,
        provenance_rule: str,
    ) -> None:
        """Insert a chain edge; silently ignores duplicate (chain, src, tgt, type)."""
        now = _utcnow()

        async def _insert(session):
            stmt = (
                pg_insert(ChainEdge)
                .values(
                    chain_id=chain_id,
                    source_finding_id=source_finding_id,
                    target_finding_id=target_finding_id,
                    edge_type=edge_type,
                    confidence=confidence,
                    provenance_rule=provenance_rule,
                    created_at=now,
                )
                .on_conflict_do_nothing(constraint="uq_chain_edge_dedup")
            )
            await session.execute(stmt)
            # Also update parent chain's last_updated_at
            await session.execute(
                update(Chain)
                .where(Chain.id == chain_id)
                .values(last_updated_at=now)
            )

        run_db(_insert)

    def get_edges(self, chain_id: str) -> list[dict[str, Any]]:
        """Return all edges for a chain."""

        async def _fetch(session):
            result = await session.execute(
                select(ChainEdge).where(ChainEdge.chain_id == chain_id)
            )
            rows = result.scalars().all()
            return [
                {
                    "id": r.id,
                    "chain_id": r.chain_id,
                    "source_finding_id": r.source_finding_id,
                    "target_finding_id": r.target_finding_id,
                    "edge_type": r.edge_type,
                    "confidence": r.confidence,
                    "provenance_rule": r.provenance_rule,
                    "created_at": r.created_at,
                }
                for r in rows
            ]

        return run_db(_fetch)
