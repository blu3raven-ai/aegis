"""PostgreSQL-based notification storage."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import Notification
from src.shared.paths import dt_to_iso as _dt_to_iso, now_iso as _now_iso

MAX_NOTIFICATIONS = 200


def _notif_to_dict(notif: Notification) -> dict[str, Any]:
    return {
        "id": notif.id,
        "type": notif.type or "",
        "category": notif.category or "",
        "severity": notif.severity or "info",
        "title": notif.title or "",
        "message": notif.message or "",
        "context": notif.metadata_json or {},
        "link": notif.link,
        "createdAt": _dt_to_iso(notif.created_at) or _now_iso(),
        "read": notif.read,
    }


async def insert_notification(
    session,
    user_id: str,
    *,
    notification_type: str,
    category: str,
    severity: str,
    title: str,
    message: str,
    context: dict[str, Any] | None = None,
    link: str | None = None,
) -> dict[str, Any]:
    """Insert one notification row on an existing async session, enforcing the
    per-user retention cap. Use this from async request handlers (which already
    hold a session); use `emit_notification` from sync contexts."""
    notif = Notification(
        id=f"notif_{uuid.uuid4().hex[:12]}",
        user_id=user_id,
        type=notification_type,
        category=category,
        severity=severity,
        title=title,
        message=message,
        metadata_json=context or {},
        link=link,
        read=False,
        created_at=datetime.now(timezone.utc),
    )
    session.add(notif)
    await session.flush()

    # Enforce retention limit per user
    count_result = await session.execute(
        select(func.count()).select_from(Notification).where(Notification.user_id == user_id)
    )
    total = count_result.scalar() or 0
    if total > MAX_NOTIFICATIONS:
        oldest = await session.execute(
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.asc())
            .limit(total - MAX_NOTIFICATIONS)
        )
        for old in oldest.scalars().all():
            await session.delete(old)

    return _notif_to_dict(notif)


def emit_notification(
    user_id: str,
    *,
    notification_type: str,
    category: str,
    severity: str,
    title: str,
    message: str,
    context: dict[str, Any] | None = None,
    link: str | None = None,
) -> dict[str, Any]:
    """Create and store a notification for a user. Returns the new notification."""
    async def _query(session):
        return await insert_notification(
            session,
            user_id,
            notification_type=notification_type,
            category=category,
            severity=severity,
            title=title,
            message=message,
            context=context,
            link=link,
        )

    return run_db(_query)


def emit_notification_to_all(
    user_ids: list[str],
    **kwargs: Any,
) -> None:
    """Emit the same notification to multiple users in a single transaction."""
    now = datetime.now(timezone.utc)

    async def _query(session):
        for uid in user_ids:
            session.add(Notification(
                id=f"notif_{uuid.uuid4().hex[:12]}",
                user_id=uid,
                type=kwargs.get("notification_type", ""),
                category=kwargs.get("category", ""),
                severity=kwargs.get("severity", "info"),
                title=kwargs.get("title", ""),
                message=kwargs.get("message", ""),
                metadata_json=kwargs.get("context") or {},
                link=kwargs.get("link"),
                read=False,
                created_at=now,
            ))

    run_db(_query)


def get_notifications(
    user_id: str,
    *,
    unread_only: bool = False,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """Return (notifications, total_count) for a user."""
    async def _query(session):
        stmt = select(Notification).where(Notification.user_id == user_id)
        if unread_only:
            stmt = stmt.where(Notification.read == False)  # noqa: E712

        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

        # Get paginated results
        stmt = stmt.order_by(Notification.created_at.desc()).offset(offset).limit(limit)
        result = await session.execute(stmt)
        notifs = [_notif_to_dict(n) for n in result.scalars().all()]
        return notifs, total

    return run_db(_query)


def get_unread_count(user_id: str) -> int:
    async def _query(session):
        result = await session.execute(
            select(func.count()).select_from(Notification).where(
                Notification.user_id == user_id,
                Notification.read == False,  # noqa: E712
            )
        )
        return result.scalar() or 0

    return run_db(_query)


def mark_as_read(user_id: str, notification_id: str | None = None) -> int:
    """Mark one notification or all as read. Returns count marked."""
    async def _query(session):
        stmt = select(Notification).where(
            Notification.user_id == user_id,
            Notification.read == False,  # noqa: E712
        )
        if notification_id is not None:
            stmt = stmt.where(Notification.id == notification_id)
        result = await session.execute(stmt)
        notifs = result.scalars().all()
        for n in notifs:
            n.read = True
        return len(notifs)

    return run_db(_query)


def delete_notification(user_id: str, notification_id: str) -> bool:
    async def _query(session):
        result = await session.execute(
            select(Notification).where(
                Notification.user_id == user_id,
                Notification.id == notification_id,
            )
        )
        notif = result.scalars().first()
        if notif:
            await session.delete(notif)
            return True
        return False

    return run_db(_query)
