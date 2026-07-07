"""EmitInterface — idempotent write layer for correlation rule outputs.

Rules call emit_* methods rather than writing to the DB directly. This
keeps rules thin and ensures:

1. Idempotency: every emit is keyed by (rule_name, source_event_id, target_id).
   The key is written to Redis so repeat calls are no-ops.
2. Audit: every emitted finding/chain is tagged with its provenance rule.
3. Event fanout: emits publish back to the durable event bus so downstream
   consumers (UI SSE, alerting) see the correlation output.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any

import redis

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.event_emit_helpers import _emit
from src.shared.event_publisher import get_event_publisher
from src.shared.event_types.finding import (
    ChainCreatedEvent,
    ChainUpdatedEvent,
    FindingClosedEvent,
    FindingCreatedEvent,
    FindingSeverityChangedEvent,
)
from src.shared.finding_queries import upsert_finding, update_finding_state
from src.correlation.chain_graph_store import ChainGraphStore
from sqlalchemy import select, update as sa_update

logger = logging.getLogger(__name__)

# Redis TTL for idempotency keys — long enough to cover re-delivery windows.
_IDEMPOTENCY_TTL_SECONDS = 24 * 3600  # 1 day


def _idem_key(rule_name: str, event_id: str, target_id: str) -> str:
    return f"correlation:idempotency:{rule_name}:{event_id}:{target_id}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class EmitInterface:
    """Write layer injected into every rule via RuleContext.

    Constructor accepts a Redis client for idempotency checks and a
    ChainGraphStore for chain persistence. Both are injected so tests can
    provide fakes.
    """

    def __init__(
        self,
        redis_client: redis.Redis,
        chain_store: ChainGraphStore,
    ) -> None:
        self._redis = redis_client
        self._chain_store = chain_store

    # ── public API ────────────────────────────────────────────────────────────

    def emit_finding(
        self,
        finding_data: dict[str, Any],
        *,
        source_event_id: str,
        rule_name: str,
    ) -> str | None:
        """Upsert a finding and return its integer id as a string.

        Returns None if the emit was a duplicate (idempotency guard fired).
        finding_data must contain: tool, org, identity_key, severity, detail.
        Optional: repo, state (defaults to 'open').
        """
        identity_key = finding_data["identity_key"]
        idem_key = _idem_key(rule_name, source_event_id, identity_key)
        if self._redis.exists(idem_key):
            logger.debug("emit_finding: duplicate suppressed rule=%s event=%s key=%s",
                         rule_name, source_event_id, identity_key)
            return None

        tool = finding_data["tool"]
        org = finding_data["org"]
        repo = finding_data.get("repo")
        state = finding_data.get("state", "open")
        severity = finding_data.get("severity")
        detail = finding_data.get("detail", {})
        # Tag the provenance so analysts know this was correlation-derived
        detail = {**detail, "provenance_rule": rule_name}

        async def _upsert(session):
            return await upsert_finding(
                session,
                tool=tool,
                asset_id=finding_data.get("asset_id"),
                org=org,
                repo=repo,
                identity_key=identity_key,
                state=state,
                severity=severity,
                detail=detail,
            )

        finding = run_db(_upsert)
        finding_id = str(finding.id)

        self._redis.set(idem_key, "1", ex=_IDEMPOTENCY_TTL_SECONDS)

        _emit_event(FindingCreatedEvent(
            org_id=org,
            source_component="correlation_engine",
            payload={
                "finding_id": finding_id,
                "severity": severity,
                "scanner_type": tool,
                "provenance_rule": rule_name,
            },
        ))

        return finding_id

    def emit_chain(
        self,
        chain_data: dict[str, Any],
        *,
        source_event_id: str,
        rule_name: str,
    ) -> str | None:
        """Create a chain and return its ULID id.

        Returns None if duplicate (idempotency guard fired).
        chain_data must contain: org_id, chain_type, severity.
        Optional: status (defaults to 'open').
        """
        # Idempotency key uses a stable hash of (org, type, rule, event) because
        # chain_id is generated fresh each time — dedupe on the logical tuple.
        dedup_str = f"{chain_data['org_id']}:{chain_data['chain_type']}:{rule_name}:{source_event_id}"
        dedup_hash = hashlib.sha256(dedup_str.encode()).hexdigest()[:16]
        idem_key = _idem_key(rule_name, source_event_id, f"chain:{dedup_hash}")

        # Use a single GET rather than EXISTS+GET to avoid a race where the key
        # expires between the two calls and we'd silently return None.
        existing = self._redis.get(idem_key)
        if existing is not None:
            if isinstance(existing, bytes):
                existing = existing.decode()
            logger.debug("emit_chain: duplicate, returning existing chain=%s rule=%s event=%s",
                         existing, rule_name, source_event_id)
            return existing

        chain_id = self._chain_store.create_chain(
            org_id=chain_data["org_id"],
            chain_type=chain_data["chain_type"],
            severity=chain_data["severity"],
            status=chain_data.get("status", "open"),
        )

        self._redis.set(idem_key, chain_id, ex=_IDEMPOTENCY_TTL_SECONDS)

        _emit_event(ChainCreatedEvent(
            org_id=chain_data["org_id"],
            source_component="correlation_engine",
            payload={
                "chain_id": chain_id,
                "chain_type": chain_data["chain_type"],
                "severity": chain_data["severity"],
                "provenance_rule": rule_name,
            },
        ))

        return chain_id

    def lookup_chain(
        self,
        org_id: str,
        chain_type: str,
        source_event_id: str,
        rule_name: str,
    ) -> str | None:
        """Return the stored chain_id for the given anchor parameters, or None.

        Uses the same idempotency key as emit_chain. Call this when emit_chain
        returns None so edges can still be added to the existing chain.
        Returns None if the idempotency entry has expired from Redis.
        """
        dedup_str = f"{org_id}:{chain_type}:{rule_name}:{source_event_id}"
        dedup_hash = hashlib.sha256(dedup_str.encode()).hexdigest()[:16]
        idem_key = _idem_key(rule_name, source_event_id, f"chain:{dedup_hash}")
        existing = self._redis.get(idem_key)
        if existing is not None:
            if isinstance(existing, bytes):
                existing = existing.decode()
            return existing
        return None

    def emit_chain_edge(
        self,
        chain_id: str,
        source_finding_id: int,
        target_finding_id: int,
        edge_type: str,
        *,
        confidence: float,
        rule_name: str,
    ) -> None:
        """Add a directed edge to a chain.

        Silently no-ops on duplicate (uq_chain_edge_dedup constraint handles it
        at the DB layer; we also guard at Redis for speed).
        """
        idem_key = _idem_key(
            rule_name,
            chain_id,
            f"edge:{source_finding_id}:{target_finding_id}:{edge_type}",
        )
        if self._redis.exists(idem_key):
            return

        self._chain_store.add_edge(
            chain_id=chain_id,
            source_finding_id=source_finding_id,
            target_finding_id=target_finding_id,
            edge_type=edge_type,
            confidence=confidence,
            provenance_rule=rule_name,
        )
        self._redis.set(idem_key, "1", ex=_IDEMPOTENCY_TTL_SECONDS)

        # Notify consumers that the chain gained a new edge
        _emit_event(ChainUpdatedEvent(
            org_id="",  # not available here; consumers look up chain by id
            source_component="correlation_engine",
            payload={
                "chain_id": chain_id,
                "edges_added": [{
                    "source": source_finding_id,
                    "target": target_finding_id,
                    "edge_type": edge_type,
                    "confidence": confidence,
                }],
                "edges_removed": [],
                "provenance_rule": rule_name,
            },
        ))

    def emit_severity_change(
        self,
        finding_id: int,
        new_severity: str,
        *,
        reason: str,
        rule_name: str,
    ) -> None:
        """Update finding severity and emit FindingSeverityChangedEvent."""
        idem_key = _idem_key(rule_name, str(finding_id), f"severity:{new_severity}")
        if self._redis.exists(idem_key):
            return

        async def _update(session):
            result = await session.execute(
                select(Finding).where(Finding.id == finding_id)
            )
            row = result.scalars().first()
            if row is None:
                return None
            old_severity = row.severity
            row.severity = new_severity
            row.updated_at = _utcnow()
            return old_severity

        old_severity = run_db(_update)
        if old_severity is None:
            logger.warning("emit_severity_change: finding %d not found", finding_id)
            return

        self._redis.set(idem_key, "1", ex=_IDEMPOTENCY_TTL_SECONDS)

        async def _fetch_org(session):
            result = await session.execute(
                select(Finding.org).where(Finding.id == finding_id)
            )
            return result.scalar_one_or_none()

        org_id = run_db(_fetch_org) or ""

        _emit_event(FindingSeverityChangedEvent(
            org_id=org_id,
            source_component="correlation_engine",
            payload={
                "finding_id": finding_id,
                "old": old_severity,
                "new": new_severity,
                "reason": reason,
                "provenance_rule": rule_name,
            },
        ))

    def emit_close(
        self,
        finding_id: int,
        *,
        reason: str,
        rule_name: str,
    ) -> None:
        """Close a finding (set state = 'fixed') and emit FindingClosedEvent."""
        idem_key = _idem_key(rule_name, str(finding_id), "close")
        if self._redis.exists(idem_key):
            return

        async def _close(session):
            result = await session.execute(
                select(Finding).where(Finding.id == finding_id)
            )
            row = result.scalars().first()
            if row is None:
                return None
            await update_finding_state(session, row, "fixed")
            return row.org

        org_id = run_db(_close)
        if org_id is None:
            logger.warning("emit_close: finding %d not found", finding_id)
            return

        self._redis.set(idem_key, "1", ex=_IDEMPOTENCY_TTL_SECONDS)

        _emit_event(FindingClosedEvent(
            org_id=org_id,
            source_component="correlation_engine",
            payload={
                "finding_id": finding_id,
                "reason": reason,
                "provenance_rule": rule_name,
            },
        ))


# ── private helpers ───────────────────────────────────────────────────────────


def _emit_event(event) -> None:
    """Publish to the durable event bus; never raises into the caller."""
    try:
        get_event_publisher().publish(event)
    except Exception:
        logger.exception("emit_interface: durable publish failed for %s", event.event_type)
