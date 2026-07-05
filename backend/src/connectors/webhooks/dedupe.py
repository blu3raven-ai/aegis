"""Inbound-webhook replay deduplication.

A provider may re-send a webhook (its own retry, or an attacker replaying a
captured request) with an identical body and a still-valid signature. Without
a per-delivery record, the receiver would republish it and re-trigger a scan.

Each provider stamps a delivery with a unique id header (``X-GitHub-Delivery``,
``X-Gitlab-Event-UUID``, ``X-Request-UUID``). :func:`register_delivery` records
``(provider, delivery_id)`` atomically via the table's unique constraint, so a
second appearance of the same delivery is recognised and dropped.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import WebhookProcessedDelivery, utcnow

logger = logging.getLogger(__name__)

# Approximate GC: prune once every N successful inserts instead of running a
# dedicated background worker. Cleanup is best-effort — an occasional miss just
# leaves a few extra rows until the next insert crosses the threshold.
_PRUNE_EVERY = 500
_insert_counter = 0


def register_delivery(provider: str, delivery_id: str) -> bool:
    """Record a delivery, returning ``True`` if it is a duplicate.

    Atomicity comes from the ``uq_webhook_delivery_provider_id`` unique
    constraint rather than a check-then-insert (which would race two concurrent
    replays). We attempt the INSERT; a unique violation surfaces as
    ``IntegrityError``, which we treat as "already recorded". The rollback is
    handled inside this function's own transaction so a duplicate never poisons
    a caller's session state.
    """
    global _insert_counter

    async def _insert(session: AsyncSession) -> bool:
        session.add(WebhookProcessedDelivery(provider=provider, delivery_id=delivery_id))
        try:
            await session.flush()
        except IntegrityError:
            await session.rollback()
            return True
        return False

    is_duplicate = run_db(_insert)

    if not is_duplicate:
        _insert_counter += 1
        if _insert_counter % _PRUNE_EVERY == 0:
            try:
                prune_old_deliveries()
            except Exception:
                # Cleanup must never break ingest.
                logger.warning("webhook.dedupe: prune failed", exc_info=True)

    return is_duplicate


def prune_old_deliveries(older_than_days: int = 7) -> int:
    """Delete delivery records older than ``older_than_days``; return the count."""
    cutoff = utcnow() - timedelta(days=older_than_days)

    async def _prune(session: AsyncSession) -> int:
        result = await session.execute(
            delete(WebhookProcessedDelivery).where(
                WebhookProcessedDelivery.received_at < cutoff
            )
        )
        return result.rowcount or 0

    return run_db(_prune)
