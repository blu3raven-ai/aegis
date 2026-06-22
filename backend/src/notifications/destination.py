"""CRUD helpers for notification_destinations and notification_deliveries."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import NotificationDestination, NotificationDelivery

logger = logging.getLogger(__name__)

VALID_DEST_TYPES = frozenset({"slack", "webhook", "email"})
VALID_STATUSES = frozenset({"pending", "delivered", "failed", "retry"})


def _dest_to_dict(dest: NotificationDestination) -> dict[str, Any]:
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
            config=config,
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
            dest.config = config
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
) -> dict[str, Any]:
    """Insert or update the delivery record for (destination_id, event_id)."""
    now = datetime.now(timezone.utc)

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


def list_pending_retries(limit: int = 100) -> list[dict[str, Any]]:
    """Return deliveries in 'retry' status, oldest first, for the retry worker."""
    async def _q(session):
        result = await session.execute(
            select(NotificationDelivery)
            .where(NotificationDelivery.status == "retry")
            .order_by(NotificationDelivery.attempted_at.asc())
            .limit(limit)
        )
        return [_delivery_to_dict(d) for d in result.scalars().all()]

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
