"""Tests for notification-delivery retry: backoff maths, the failed-first-send
retry enqueue, and the retry worker's re-send / backoff / give-up transitions.

The DB-backed cases run the real store helpers (via ``run_db``) against Postgres
so schema drift on the new retry columns can't hide behind mocks.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy import delete as sa_delete, select, update as sa_update

from src.connectors.base import SendResult
from src.db.models import NotificationDelivery, NotificationDestination
from src.notifications.destination import (
    MAX_DELIVERY_ATTEMPTS,
    create_destination,
    next_attempt_at,
    record_delivery,
)
from src.notifications.retry_worker import _process_tick


# -----------------------------------------------------------------------------
# Pure: backoff schedule + give-up constant.
# -----------------------------------------------------------------------------


def test_next_attempt_at_first_attempt_is_base_delay():
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    assert (next_attempt_at(1, now) - now).total_seconds() == 60


def test_next_attempt_at_is_monotonic_and_capped():
    now = datetime(2026, 7, 1, tzinfo=timezone.utc)
    delays = [(next_attempt_at(a, now) - now).total_seconds() for a in range(1, 10)]
    # Non-decreasing (doubles until the cap, then plateaus).
    assert delays == sorted(delays)
    # Doubling early on.
    assert delays[0] == 60
    assert delays[1] == 120
    assert delays[2] == 240
    # Never exceeds the one-hour cap, and reaches it.
    assert max(delays) == 3600
    assert all(d <= 3600 for d in delays)


def test_max_delivery_attempts_constant():
    assert MAX_DELIVERY_ATTEMPTS == 5


# -----------------------------------------------------------------------------
# DB-backed fixtures.
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture
async def destinations_cleanup(db_session):
    created_ids: list[int] = []
    yield created_ids
    if created_ids:
        await db_session.execute(
            sa_delete(NotificationDelivery).where(
                NotificationDelivery.destination_id.in_(created_ids)
            )
        )
        await db_session.execute(
            sa_delete(NotificationDestination).where(
                NotificationDestination.id.in_(created_ids)
            )
        )
        await db_session.commit()


async def _fetch_delivery(db_session, destination_id, event_id):
    # Writes land via run_db's separate engine; expire the identity map so we
    # re-read committed column values rather than stale in-session copies.
    db_session.expire_all()
    result = await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == destination_id,
            NotificationDelivery.event_id == event_id,
        )
    )
    return result.scalars().first()


async def _force_due(db_session, destination_id, event_id):
    """Backdate next_attempt_at so the worker treats the row as due again."""
    await db_session.execute(
        sa_update(NotificationDelivery)
        .where(
            NotificationDelivery.destination_id == destination_id,
            NotificationDelivery.event_id == event_id,
        )
        .values(next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1))
    )
    await db_session.commit()


# -----------------------------------------------------------------------------
# Failed first send -> retry row.
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_first_send_parks_delivery_for_retry(db_session, destinations_cleanup):
    from src.shared.event_bus import Event
    from src.notifications.router_event import NotificationEventRouter

    name = f"retry-webhook-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "https://example.test/hook"},
        enabled=True,
    )
    destinations_cleanup.append(created["id"])

    dest_dict = {
        "id": created["id"],
        "destination_type": "webhook",
        "name": name,
        "config": {"url": "https://example.test/hook"},
        "event_filter": None,
    }
    event_id = f"evt-{uuid4().hex[:8]}"
    event = Event(
        event_type="finding.created",
        data={"event_id": event_id, "org_id": "", "payload": {"severity": "high", "summary": "boom"}},
    )

    with patch(
        "src.notifications.destination.get_enabled_destinations", return_value=[dest_dict]
    ), patch(
        "src.notifications.rules_model.get_active_rules", return_value=[]
    ), patch(
        "src.notifications.dispatch.send_to_destination",
        return_value=SendResult(success=False, response_code=503, error="upstream boom"),
    ):
        NotificationEventRouter()._handle_event(event)

    row = await _fetch_delivery(db_session, created["id"], event_id)
    assert row is not None
    assert row.status == "retry"
    assert row.attempts == 1
    assert row.next_attempt_at is not None
    assert row.next_attempt_at > datetime.now(timezone.utc)
    # Full formatted payload retained so the worker can re-send without the event.
    assert row.payload is not None and row.payload.strip().startswith("{")


# -----------------------------------------------------------------------------
# Worker: success clears retry bookkeeping.
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_marks_delivered_and_clears_payload_on_success(
    db_session, destinations_cleanup
):
    name = f"retry-ok-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "https://example.test/hook"},
        enabled=True,
    )
    destinations_cleanup.append(created["id"])

    event_id = f"evt-{uuid4().hex[:8]}"
    record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="retry",
        attempts=1,
        next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        payload='{"text": "hi"}',
    )

    with patch(
        "src.notifications.dispatch.send_to_destination",
        return_value=SendResult(success=True, response_code=200),
    ):
        _process_tick()

    row = await _fetch_delivery(db_session, created["id"], event_id)
    assert row.status == "delivered"
    assert row.response_code == 200
    assert row.next_attempt_at is None
    assert row.payload is None


# -----------------------------------------------------------------------------
# Worker: repeated failure increments attempts, then gives up at MAX.
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_backs_off_then_gives_up_at_max(db_session, destinations_cleanup):
    name = f"retry-fail-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "https://example.test/hook"},
        enabled=True,
    )
    destinations_cleanup.append(created["id"])

    event_id = f"evt-{uuid4().hex[:8]}"
    record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="retry",
        attempts=1,
        next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        payload='{"text": "hi"}',
    )

    seen_attempts: list[int] = []
    with patch(
        "src.notifications.dispatch.send_to_destination",
        return_value=SendResult(success=False, response_code=500, error="still down"),
    ):
        # Drive ticks until the delivery gives up, forcing it due each round.
        for _ in range(MAX_DELIVERY_ATTEMPTS + 2):
            _process_tick()
            row = await _fetch_delivery(db_session, created["id"], event_id)
            seen_attempts.append(row.attempts)
            if row.status == "failed":
                break
            await _force_due(db_session, created["id"], event_id)

    row = await _fetch_delivery(db_session, created["id"], event_id)
    assert row.status == "failed"
    assert row.attempts == MAX_DELIVERY_ATTEMPTS
    assert row.next_attempt_at is None
    assert row.payload is None
    # Attempts strictly increased across ticks up to the cap.
    assert seen_attempts == [2, 3, 4, 5]


# -----------------------------------------------------------------------------
# Re-send goes through the SSRF-guarded shared sender, not a bypass.
# -----------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_worker_resend_applies_webhook_ssrf_guard(db_session, destinations_cleanup):
    # A retry whose stored destination points at a loopback address must be
    # rejected by the webhook sender's SSRF guard on re-send — proving the worker
    # uses the real guarded send_to_destination path, not an unguarded shortcut.
    name = f"retry-ssrf-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "http://127.0.0.1:9/hook"},
        enabled=True,
    )
    destinations_cleanup.append(created["id"])

    event_id = f"evt-{uuid4().hex[:8]}"
    record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="retry",
        attempts=1,
        next_attempt_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        payload='{"text": "hi"}',
    )

    # No send_to_destination mock: the genuine GenericWebhookSender runs and its
    # SSRF guard blocks the loopback URL.
    _process_tick()

    row = await _fetch_delivery(db_session, created["id"], event_id)
    assert row.status == "retry"
    assert row.attempts == 2
    assert "blocked" in (row.error or "").lower()
