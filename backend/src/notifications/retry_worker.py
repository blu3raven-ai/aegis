"""Background worker that re-sends failed notification deliveries with backoff.

A failed first-attempt delivery is parked in 'retry' status with its formatted
payload stored and a ``next_attempt_at`` timestamp. This loop periodically picks
up due retries and re-sends them through the same SSRF-guarded channel dispatch
path used for the initial send. Each re-send either succeeds (marked
'delivered'), schedules the next backoff attempt, or — once
``MAX_DELIVERY_ATTEMPTS`` is reached — flips to a terminal 'failed'.
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _process_tick() -> None:
    """Re-send every currently-due retry. One tick's worth of work.

    Runs entirely synchronously (DB access + blocking sender I/O) and is invoked
    off the event loop via ``asyncio.to_thread`` by the loop below. A per-delivery
    try/except ensures one bad delivery never aborts the rest of the batch.
    """
    from src.notifications.destination import (
        MAX_DELIVERY_ATTEMPTS,
        get_destination,
        list_pending_retries,
        next_attempt_at,
        record_delivery,
    )
    from src.notifications.dispatch import send_to_destination

    for item in list_pending_retries():
        try:
            dest = get_destination(item["destination_id"])
            if dest is None:
                # Destination vanished (deliveries cascade-delete with it, so
                # this is defensive) — nothing to re-send.
                logger.warning(
                    "retry skipped: destination %s no longer exists",
                    item.get("destination_id"),
                )
                continue

            raw_payload = item.get("payload")
            payload = json.loads(raw_payload) if raw_payload else {}
            result = send_to_destination(
                dest["destination_type"], payload, dest.get("config") or {}
            )
            now = datetime.now(timezone.utc)

            if result.success:
                record_delivery(
                    destination_id=item["destination_id"],
                    event_id=item["event_id"],
                    event_type=item["event_type"],
                    status="delivered",
                    response_code=result.response_code,
                    error=None,
                    next_attempt_at=None,
                    payload=None,
                )
                continue

            attempts = item["attempts"] + 1
            if attempts >= MAX_DELIVERY_ATTEMPTS:
                record_delivery(
                    destination_id=item["destination_id"],
                    event_id=item["event_id"],
                    event_type=item["event_type"],
                    status="failed",
                    attempts=attempts,
                    response_code=result.response_code,
                    error=result.error,
                    next_attempt_at=None,
                    payload=None,
                )
            else:
                record_delivery(
                    destination_id=item["destination_id"],
                    event_id=item["event_id"],
                    event_type=item["event_type"],
                    status="retry",
                    attempts=attempts,
                    response_code=result.response_code,
                    error=result.error,
                    next_attempt_at=next_attempt_at(attempts, now),
                )
        except Exception:
            logger.warning(
                "notification retry re-send failed for delivery %s",
                item.get("id"),
                exc_info=True,
            )


async def _sleep_or_stop(seconds: float, stop_event: asyncio.Event) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass


async def retry_worker_loop(
    stop_event: asyncio.Event, *, interval_s: float = 30.0
) -> None:
    """Poll for due retries every ``interval_s`` seconds until ``stop_event`` set."""
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(_process_tick)
        except Exception:
            logger.warning("notification retry worker tick failed", exc_info=True)
        await _sleep_or_stop(interval_s, stop_event)
