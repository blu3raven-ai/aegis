"""Audit-stream background poster.

Idempotency contract: every outbound payload row carries an `event_id` field
equal to the monotonic `audit_events.id` primary key. Receivers should dedup
by `event_id` per row, because replay can occur when the receiver successfully
processes a batch but the ack is lost in transit before the poster advances
its cursor — the next tick will redeliver the same range. PKs are never
reassigned, so `event_id` is stable across replays.

As belt-and-suspenders on the poster side, a small bounded in-memory cache of
recent successfully-delivered batch hashes lets a single process short-circuit
a same-batch replay (POST → ack lost → cursor stuck → next tick rebuilds the
identical batch) by advancing the cursor without re-POSTing. The cache is
process-local and does not survive restart; cross-restart dedup relies on
receiver-side `event_id` matching.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
from collections import deque
from datetime import date, datetime, timezone
from uuid import UUID

from sqlalchemy import select

from src.audit_stream.adapters import (
    splunk_hec_deliver,
    syslog_deliver,
    webhook_deliver,
)
from src.db.helpers import run_db
from src.db.models import AuditEvent, AuditStreamConfig
from src.security.crypto import decrypt
from src.shared.ha import try_advisory_lock

BATCH_SIZE = 100
POLL_INTERVAL_SECONDS = 5
BACKOFF_STEPS_SECONDS = [1, 5, 30, 300]
RECENT_BATCH_HASH_CAPACITY = 16

# Postgres advisory-lock key that elects exactly one poster across HA replicas.
# Derivation: first 8 bytes of SHA-256("aegis_audit_stream_poster"), big-endian,
# signed two's-complement. Future advisory-lock callers in this codebase must
# follow the same sha256[:8] / signed=True convention (see shared/ha.py) so
# collisions require a real SHA-256 prefix collision, not just a hash-and-mask
# clash. If you add a second lock, pick a different ASCII tag and document its
# integer next to the call site. The accompanying test in
# test_audit_stream_advisory_lock.py pins this value so accidental drift in the
# derivation surfaces immediately.
AUDIT_POSTER_ADVISORY_LOCK_KEY: int = int.from_bytes(
    hashlib.sha256(b"aegis_audit_stream_poster").digest()[:8],
    "big",
    signed=True,
)

_recent_batch_hashes: deque[str] = deque(maxlen=RECENT_BATCH_HASH_CAPACITY)


def _json_default(value: object) -> str:
    # Typed fallback for _batch_hash. `default=str` would hash any object via
    # its repr (which can embed a memory address) — a new non-serialisable
    # payload type would then hash differently every tick and silently break
    # dedup. Handle the known temporal/UUID types and raise on anything else so
    # the regression fails loudly in tests instead.
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    raise TypeError(f"Unhashable audit-event field type: {type(value).__name__}")


def _batch_hash(events: list[dict]) -> str:
    return hashlib.sha256(
        json.dumps(events, sort_keys=True, default=_json_default).encode("utf-8")
    ).hexdigest()


def _event_to_dict(evt: AuditEvent) -> dict:
    return {
        "event_id": evt.id,
        "id": evt.id,
        "timestamp": evt.created_at.isoformat() if evt.created_at else None,
        "action": evt.action,
        "resource": {
            "type": evt.resource_type,
            "id": evt.resource_id,
        },
        "actor": {
            "id": evt.actor_user_id,
            "username": evt.actor_username,
            "email": evt.actor_email,
        },
        "metadata": evt.metadata_json or {},
    }


async def deliver_batch_once() -> dict:
    # Gate the entire read → POST → cursor-write sequence behind a Postgres
    # advisory lock so HA replicas elect exactly one deliverer per batch.
    # ``pg_try_advisory_lock`` is non-blocking; the non-holder returns a no-op
    # and the next tick re-races for the lock.
    async with try_advisory_lock(AUDIT_POSTER_ADVISORY_LOCK_KEY) as acquired:
        if not acquired:
            return {"delivered": 0, "skipped": True, "reason": "lock_held"}

        async def _read(session):
            cfg = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one()
            if not cfg.enabled or cfg.target_type is None or cfg.endpoint_url is None:
                return None
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.id > cfg.last_event_id)
                .order_by(AuditEvent.id)
                .limit(BATCH_SIZE)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return {
                "target_type": cfg.target_type,
                "endpoint_url": cfg.endpoint_url,
                "token": decrypt(cfg.auth_token_enc) if cfg.auth_token_enc else None,
                "events": [_event_to_dict(r) for r in rows],
                "last_id": rows[-1].id if rows else cfg.last_event_id,
            }

        snap = run_db(_read)
        if snap is None:
            return {"delivered": 0, "skipped": True}
        if not snap["events"]:
            return {"delivered": 0, "skipped": False}

        batch_hash = _batch_hash(snap["events"])
        if batch_hash in _recent_batch_hashes:
            # Already delivered this exact batch in-process; the prior cursor-write
            # must have failed. Skip the re-POST and let the write below advance.
            result: dict = {"ok": True, "error": None}
            deduped = True
        else:
            deduped = False
            if snap["target_type"] == "webhook":
                result = await webhook_deliver(snap["endpoint_url"], snap["token"], snap["events"])
            elif snap["target_type"] == "splunk_hec":
                result = await splunk_hec_deliver(snap["endpoint_url"], snap["token"], snap["events"])
            elif snap["target_type"] == "syslog":
                result = await syslog_deliver(snap["endpoint_url"], snap["token"], snap["events"])
            else:
                result = {"ok": False, "error": f"Unknown target_type: {snap['target_type']}"}
            # Record the successful POST BEFORE the cursor-write attempt, so a
            # write-side crash on the next tick can short-circuit re-POST.
            if result["ok"]:
                _recent_batch_hashes.append(batch_hash)

        async def _write(session):
            cfg = (await session.execute(select(AuditStreamConfig).where(AuditStreamConfig.id == 1))).scalar_one()
            if result["ok"]:
                cfg.last_event_id = snap["last_id"]
                cfg.last_success_at = datetime.now(timezone.utc)
                cfg.last_error = None
            else:
                cfg.last_error = (result.get("error") or "")[:500]
        run_db(_write)

        return {
            "delivered": len(snap["events"]) if result["ok"] else 0,
            "skipped": False,
            "error": result.get("error"),
            "deduped": deduped,
        }


async def poster_loop(stop_event: asyncio.Event) -> None:
    backoff_idx = 0
    while not stop_event.is_set():
        result = await deliver_batch_once()
        if result.get("skipped"):
            await _sleep_or_stop(POLL_INTERVAL_SECONDS, stop_event)
            backoff_idx = 0
            continue
        if result.get("error"):
            delay = BACKOFF_STEPS_SECONDS[min(backoff_idx, len(BACKOFF_STEPS_SECONDS) - 1)]
            backoff_idx += 1
            await _sleep_or_stop(delay, stop_event)
        else:
            backoff_idx = 0
            await _sleep_or_stop(POLL_INTERVAL_SECONDS, stop_event)


async def _sleep_or_stop(seconds: float, stop_event: asyncio.Event) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        pass
