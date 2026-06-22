"""Concurrency tests for the audit-stream poster's Postgres advisory lock.

The lock is what makes the lifespan poster HA-safe: if Aegis runs two backend
instances, both schedule their own ``poster_loop`` task and would otherwise
each deliver every batch, doubling the payload at the SIEM. These tests
exercise the actual ``pg_try_advisory_lock`` call against a real Postgres so
the guarantee is not a mock.
"""
from __future__ import annotations

import asyncio
import hashlib
import os

os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)
os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")

from datetime import datetime, timezone  # noqa: E402
from unittest.mock import patch  # noqa: E402
from uuid import uuid4  # noqa: E402

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from sqlalchemy import delete, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402

from src.audit_stream import poster  # noqa: E402
from src.db.models import AuditEvent, AuditStreamConfig  # noqa: E402


def test_advisory_lock_key_constant_is_stable():
    """Pin the int64 derivation so a refactor of the constant surfaces here.

    The lock key is derived as the signed two's-complement big-endian int of
    the first 8 bytes of SHA-256("aegis_audit_stream_poster"). Any change to
    the derivation invalidates running HA deployments (two instances on
    different keys would both deliver) so it must be caught immediately.
    """
    expected = int.from_bytes(
        hashlib.sha256(b"aegis_audit_stream_poster").digest()[:8],
        "big",
        signed=True,
    )
    assert poster.AUDIT_POSTER_ADVISORY_LOCK_KEY == expected
    # And pin the literal so changing the input tag also fails the test.
    assert poster.AUDIT_POSTER_ADVISORY_LOCK_KEY == 3122667887268203848


@pytest_asyncio.fixture
async def _audit_db_state(db_session: AsyncSession):
    """Seed a singleton AuditStreamConfig + a clean audit_events table.

    The audit_stream_config row has a singleton CHECK constraint (id=1) so we
    can't just delete the row without breaking other tests; we upsert it back
    to a disabled state at teardown.
    """
    await db_session.execute(delete(AuditEvent))
    existing = (
        await db_session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))
    ).scalar_one_or_none()
    if existing is None:
        cfg = AuditStreamConfig(
            id=1,
            enabled=True,
            target_type="webhook",
            endpoint_url="https://hook.example.test/audit",
            auth_token_enc=None,
            last_event_id=0,
        )
        db_session.add(cfg)
    else:
        existing.enabled = True
        existing.target_type = "webhook"
        existing.endpoint_url = "https://hook.example.test/audit"
        existing.auth_token_enc = None
        existing.last_event_id = 0
        existing.last_success_at = None
        existing.last_error = None
    await db_session.commit()

    yield db_session

    poster._recent_batch_hashes.clear()
    await db_session.execute(delete(AuditEvent))
    existing = (
        await db_session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))
    ).scalar_one_or_none()
    if existing is not None:
        existing.enabled = False
        existing.target_type = None
        existing.endpoint_url = None
        existing.auth_token_enc = None
        existing.last_event_id = 0
        existing.last_success_at = None
        existing.last_error = None
    await db_session.commit()


async def _seed_events(session: AsyncSession, n: int) -> list[int]:
    ids: list[int] = []
    for i in range(n):
        evt = AuditEvent(
            action=f"test.ha.{uuid4()}",
            actor_user_id="ha-tester",
            actor_username="ha-tester",
            actor_email="ha@example.test",
            resource_type="test",
            resource_id=str(i),
            metadata_json={"i": i},
            created_at=datetime.now(timezone.utc),
        )
        session.add(evt)
        await session.flush()
        ids.append(evt.id)
    await session.commit()
    return ids


@pytest.mark.asyncio
async def test_concurrent_posters_do_not_double_deliver(_audit_db_state):
    """Two concurrent calls to deliver_batch_once must elect exactly one deliverer.

    The loser sees the lock as held and returns a no-op; the winner POSTs the
    batch once and advances the cursor. Across both tasks the union of
    delivered event_ids must equal the seeded set, with no duplicates.
    """
    seeded_ids = await _seed_events(_audit_db_state, 5)

    delivered_batches: list[list[int]] = []
    # Hold the webhook call briefly so the two tasks overlap inside the lock
    # window — without the latency the first call could complete before the
    # second one even races for the lock and the test wouldn't prove anything.
    start_gate = asyncio.Event()

    async def fake_webhook(url, token, payload, transport=None):
        await start_gate.wait()
        delivered_batches.append([row["event_id"] for row in payload])
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        task_a = asyncio.create_task(poster.deliver_batch_once())
        task_b = asyncio.create_task(poster.deliver_batch_once())
        # Yield a few times so both tasks reach the lock + adapter call.
        for _ in range(10):
            await asyncio.sleep(0.05)
        start_gate.set()
        result_a, result_b = await asyncio.gather(task_a, task_b)

    results = [result_a, result_b]
    winners = [r for r in results if r.get("delivered", 0) > 0]
    losers = [r for r in results if r.get("reason") == "lock_held"]

    assert len(winners) == 1, f"exactly one task should deliver; got {results}"
    assert len(losers) == 1, f"exactly one task should see the lock held; got {results}"
    assert winners[0]["delivered"] == len(seeded_ids)
    assert losers[0] == {"delivered": 0, "skipped": True, "reason": "lock_held"}

    # No double-delivery: the adapter ran exactly once with the full batch.
    assert len(delivered_batches) == 1
    assert sorted(delivered_batches[0]) == sorted(seeded_ids)

    # Cursor must reflect the single successful delivery.
    cfg = (
        await _audit_db_state.execute(
            select(AuditStreamConfig).where(AuditStreamConfig.id == 1)
        )
    ).scalar_one()
    await _audit_db_state.refresh(cfg)
    assert cfg.last_event_id == max(seeded_ids)


@pytest.mark.asyncio
async def test_lock_holder_crash_hands_off_to_next_caller(_audit_db_state):
    """If the lock-holder's connection dies, the next caller must acquire it.

    Postgres advisory locks are released on connection close. We simulate a
    crashed lock-holder by opening a dedicated session, taking the lock,
    then disposing the engine without the explicit unlock. The next
    deliver_batch_once call must then succeed and resume from where the
    cursor was left.
    """
    seeded_ids = await _seed_events(_audit_db_state, 3)

    crash_engine = create_async_engine(
        os.environ["DATABASE_URL"], echo=False, pool_size=1, max_overflow=0
    )
    crash_factory = async_sessionmaker(crash_engine, class_=AsyncSession, expire_on_commit=False)
    crash_session = crash_factory()
    acquired = (
        await crash_session.execute(
            text("SELECT pg_try_advisory_lock(:k)"),
            {"k": poster.AUDIT_POSTER_ADVISORY_LOCK_KEY},
        )
    ).scalar()
    assert acquired is True, "test setup must own the lock first"

    delivered_batches: list[list[int]] = []

    async def fake_webhook(url, token, payload, transport=None):
        delivered_batches.append([row["event_id"] for row in payload])
        return {"ok": True, "error": None}

    with patch("src.audit_stream.poster.webhook_deliver", new=fake_webhook):
        # First call: lock is held by the crash_session, must skip.
        held_result = await poster.deliver_batch_once()
        assert held_result == {"delivered": 0, "skipped": True, "reason": "lock_held"}
        assert delivered_batches == []

        # Simulate crash: close the connection without unlocking. Postgres
        # auto-releases session-scoped advisory locks on connection close.
        await crash_session.close()
        await crash_engine.dispose()

        # Next call: lock is now free, must acquire and deliver.
        recovered_result = await poster.deliver_batch_once()

    assert recovered_result["delivered"] == len(seeded_ids)
    assert recovered_result["skipped"] is False
    assert len(delivered_batches) == 1
    assert sorted(delivered_batches[0]) == sorted(seeded_ids)

    cfg = (
        await _audit_db_state.execute(
            select(AuditStreamConfig).where(AuditStreamConfig.id == 1)
        )
    ).scalar_one()
    await _audit_db_state.refresh(cfg)
    assert cfg.last_event_id == max(seeded_ids)
