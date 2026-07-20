"""CRUD helpers for notification_destinations and notification_deliveries."""
from __future__ import annotations

import copy
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import NotificationDestination, NotificationDelivery
from src.shared.encryption import decrypt_string, encrypt_string, is_encrypted

# Secret-bearing keys in a destination config that must be encrypted at rest,
# consistent with every other secret class in the app. The Slack webhook URL
# embeds a bearer token in its path, so it counts.
_SECRET_CONFIG_KEYS = ("secret", "webhook_url")


def _encrypt_config_secrets(config: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of `config` with secret-bearing values encrypted."""
    out = dict(config)
    for key in _SECRET_CONFIG_KEYS:
        value = out.get(key)
        if isinstance(value, str) and value and not is_encrypted(value):
            out[key] = encrypt_string(value)
    return out


def read_config_secret(value: str | None) -> str:
    """Decrypt a config secret written by `_encrypt_config_secrets`, tolerating
    legacy cleartext values written before encryption was introduced."""
    if not value:
        return ""
    return decrypt_string(value) if is_encrypted(value) else value

logger = logging.getLogger(__name__)

VALID_DEST_TYPES = frozenset({"slack", "webhook", "email"})
VALID_STATUSES = frozenset({"pending", "delivered", "failed", "retry"})

# Terminal outcomes carry no retry bookkeeping.
_TERMINAL_STATUSES = frozenset({"delivered", "failed"})

# Give up after this many total send attempts; the delivery then flips to a
# terminal 'failed' rather than being re-queued forever.
MAX_DELIVERY_ATTEMPTS = 5

_BACKOFF_BASE_SECONDS = 60
_BACKOFF_CAP_SECONDS = 3600

# Sentinel distinguishing "caller omitted this kwarg" (leave column untouched)
# from "caller passed None" (explicitly clear the column).
_UNSET: Any = object()

_SECRET_MASK = "***"


def next_attempt_at(attempts: int, now: datetime) -> datetime:
    """Return when the next send should be attempted after ``attempts`` failures.

    Exponential backoff: 60s * 2**(attempts-1), capped at one hour. Pure and
    deterministic so the backoff schedule is unit-testable without a clock.
    """
    delay = min(_BACKOFF_BASE_SECONDS * (2 ** (attempts - 1)), _BACKOFF_CAP_SECONDS)
    return now + timedelta(seconds=delay)


def _mask_bearer_url(url: str) -> str:
    """Collapse a whole-URL credential (e.g. a Slack incoming-webhook) to its
    host, dropping the secret path/token: 'https://host/T/B/xxx' -> 'https://host/***'."""
    if not isinstance(url, str) or not url:
        return url
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host:
        return _SECRET_MASK
    netloc = f"{host}:{parts.port}" if parts.port else host
    return f"{parts.scheme or 'https'}://{netloc}/{_SECRET_MASK}"


def _strip_url_userinfo(url: str) -> str:
    """Remove embedded user:password@ credentials from a URL, leaving the rest."""
    if not isinstance(url, str) or not url:
        return url
    parts = urlsplit(url)
    if not (parts.username or parts.password):
        return url
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def redact_config(config: Any) -> Any:
    """Return a read-safe COPY of a destination config with secrets masked.

    The stored config keeps raw signing secrets so outbound signing/sending
    still works; only the serialised read path is redacted. Never mutates the
    input.
    """
    if not isinstance(config, dict):
        return config
    redacted = copy.deepcopy(config)

    entries = redacted.get("_signing_secrets")
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict):
                entry.pop("raw", None)

    if redacted.get("secret"):
        redacted["secret"] = _SECRET_MASK
    if redacted.get("webhook_url"):
        redacted["webhook_url"] = _mask_bearer_url(redacted["webhook_url"])
    if redacted.get("url"):
        redacted["url"] = _strip_url_userinfo(redacted["url"])

    return redacted


def _dest_to_dict(dest: NotificationDestination) -> dict[str, Any]:
    # Internal shape — used by the SEND path (get_enabled_destinations), so config
    # must stay UNREDACTED or senders would post to a masked URL. Redaction happens
    # at the API read boundary (_dest_to_gql) instead.
    return {
        "id": dest.id,
        "destination_type": dest.destination_type,
        "name": dest.name,
        "config": dest.config,
        "enabled": dest.enabled,
        "event_filter": dest.event_filter,
        "created_at": dest.created_at.isoformat() if dest.created_at else None,
        "updated_at": dest.updated_at.isoformat() if dest.updated_at else None,
    }


def _delivery_to_dict(d: NotificationDelivery) -> dict[str, Any]:
    return {
        "id": d.id,
        "destination_id": d.destination_id,
        "event_id": d.event_id,
        "event_type": d.event_type,
        "status": d.status,
        "payload_summary": d.payload_summary,
        "response_code": d.response_code,
        "error": d.error,
        "attempted_at": d.attempted_at.isoformat() if d.attempted_at else None,
    }




def list_destinations() -> list[dict[str, Any]]:
    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).order_by(NotificationDestination.id)
        )
        return [_dest_to_dict(d) for d in result.scalars().all()]

    return run_db(_q)


def get_destination(dest_id: int) -> dict[str, Any] | None:
    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(NotificationDestination.id == dest_id)
        )
        dest = result.scalars().first()
        return _dest_to_dict(dest) if dest else None

    return run_db(_q)


def create_destination(
    destination_type: str,
    name: str,
    config: dict[str, Any],
    enabled: bool = True,
    event_filter: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if destination_type not in VALID_DEST_TYPES:
        raise ValueError(f"destination_type must be one of {VALID_DEST_TYPES}")

    now = datetime.now(timezone.utc)

    async def _q(session):
        dest = NotificationDestination(
            destination_type=destination_type,
            name=name,
            config=_encrypt_config_secrets(config),
            enabled=enabled,
            event_filter=event_filter,
            created_at=now,
            updated_at=now,
        )
        session.add(dest)
        await session.flush()
        return _dest_to_dict(dest)

    return run_db(_q)


def update_destination(
    dest_id: int,
    *,
    name: str | None = None,
    config: dict[str, Any] | None = None,
    enabled: bool | None = None,
    event_filter: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    now = datetime.now(timezone.utc)

    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(NotificationDestination.id == dest_id)
        )
        dest = result.scalars().first()
        if dest is None:
            return None
        if name is not None:
            dest.name = name
        if config is not None:
            dest.config = _encrypt_config_secrets(config)
        if enabled is not None:
            dest.enabled = enabled
        if event_filter is not None:
            dest.event_filter = event_filter
        dest.updated_at = now
        await session.flush()
        return _dest_to_dict(dest)

    return run_db(_q)


def delete_destination(dest_id: int) -> bool:
    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(NotificationDestination.id == dest_id)
        )
        dest = result.scalars().first()
        if dest is None:
            return False
        await session.delete(dest)
        return True

    return run_db(_q)




def record_delivery(
    destination_id: int,
    event_id: str,
    event_type: str,
    status: str,
    payload_summary: str | None = None,
    response_code: int | None = None,
    error: str | None = None,
    attempts: int | None = None,
    next_attempt_at: datetime | None = _UNSET,
    payload: str | None = _UNSET,
) -> dict[str, Any]:
    """Insert or update the delivery record for (destination_id, event_id).

    ``attempts`` is left untouched when None. ``next_attempt_at`` and ``payload``
    use a sentinel default: omit them to leave the column as-is, or pass None to
    clear it. A terminal 'delivered'/'failed' status always clears both so a
    completed delivery never leaves a stale retry cursor or stored payload
    behind, regardless of what the caller passed.
    """
    now = datetime.now(timezone.utc)
    if status in _TERMINAL_STATUSES:
        next_attempt_at = None
        payload = None

    async def _q(session):
        result = await session.execute(
            select(NotificationDelivery).where(
                NotificationDelivery.destination_id == destination_id,
                NotificationDelivery.event_id == event_id,
            )
        )
        existing = result.scalars().first()
        if existing is not None:
            existing.status = status
            existing.response_code = response_code
            existing.error = error
            existing.attempted_at = now
            if attempts is not None:
                existing.attempts = attempts
            if next_attempt_at is not _UNSET:
                existing.next_attempt_at = next_attempt_at
            if payload is not _UNSET:
                existing.payload = payload
            await session.flush()
            return _delivery_to_dict(existing)

        delivery = NotificationDelivery(
            destination_id=destination_id,
            event_id=event_id,
            event_type=event_type,
            status=status,
            payload_summary=payload_summary,
            response_code=response_code,
            error=error,
            attempted_at=now,
        )
        if attempts is not None:
            delivery.attempts = attempts
        if next_attempt_at is not _UNSET:
            delivery.next_attempt_at = next_attempt_at
        if payload is not _UNSET:
            delivery.payload = payload
        session.add(delivery)
        await session.flush()
        return _delivery_to_dict(delivery)

    return run_db(_q)


def list_deliveries_for_destination(
    destination_id: int,
    limit: int = 50,
) -> list[dict[str, Any]]:
    async def _q(session):
        result = await session.execute(
            select(NotificationDelivery)
            .where(NotificationDelivery.destination_id == destination_id)
            .order_by(NotificationDelivery.attempted_at.desc())
            .limit(limit)
        )
        return [_delivery_to_dict(d) for d in result.scalars().all()]

    return run_db(_q)


def _retry_to_dict(d: NotificationDelivery) -> dict[str, Any]:
    """Projection carrying just what the retry worker needs to re-send."""
    return {
        "id": d.id,
        "destination_id": d.destination_id,
        "event_id": d.event_id,
        "event_type": d.event_type,
        "attempts": d.attempts,
        "payload": d.payload,
        "next_attempt_at": d.next_attempt_at.isoformat() if d.next_attempt_at else None,
    }


def list_pending_retries(limit: int = 100) -> list[dict[str, Any]]:
    """Return due 'retry' deliveries (next_attempt_at reached), oldest-due first."""
    now = datetime.now(timezone.utc)

    async def _q(session):
        result = await session.execute(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.status == "retry",
                NotificationDelivery.next_attempt_at.isnot(None),
                NotificationDelivery.next_attempt_at <= now,
            )
            .order_by(NotificationDelivery.next_attempt_at.asc())
            .limit(limit)
        )
        return [_retry_to_dict(d) for d in result.scalars().all()]

    return run_db(_q)


def get_enabled_destinations() -> list[dict[str, Any]]:
    async def _q(session):
        result = await session.execute(
            select(NotificationDestination).where(
                NotificationDestination.enabled == True,  # noqa: E712
            )
        )
        return [_dest_to_dict(d) for d in result.scalars().all()]

    return run_db(_q)
