"""Audit-stream background poster."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from sqlalchemy import select

from src.audit_stream.adapters import (
    splunk_hec_deliver,
    syslog_deliver,
    webhook_deliver,
)
from src.db.helpers import run_db
from src.db.models import AuditEvent, AuditStreamConfig
from src.security.crypto import decrypt

BATCH_SIZE = 100
POLL_INTERVAL_SECONDS = 5
BACKOFF_STEPS_SECONDS = [1, 5, 30, 300]


def _event_to_dict(evt: AuditEvent) -> dict:
    return {
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

    if snap["target_type"] == "webhook":
        result = await webhook_deliver(snap["endpoint_url"], snap["token"], snap["events"])
    elif snap["target_type"] == "splunk_hec":
        result = await splunk_hec_deliver(snap["endpoint_url"], snap["token"], snap["events"])
    elif snap["target_type"] == "syslog":
        result = await syslog_deliver(snap["endpoint_url"], snap["token"], snap["events"])
    else:
        result = {"ok": False, "error": f"Unknown target_type: {snap['target_type']}"}

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
