"""Per-user notification preference gates.

Producers consult these before emitting so a user who has opted out of a
notification kind (via `UserPreferences.notif_*`) doesn't receive it. Users with
no preferences row yet fall back to the column default, so a brand-new account
still gets default-on notifications.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm.attributes import InstrumentedAttribute

from src.db.models import UserPreferences


async def wants_notification(
    session,
    user_id: str,
    column: InstrumentedAttribute,
    *,
    default: bool = True,
) -> bool:
    """Whether `user_id` has the given `notif_*` preference enabled."""
    value = (
        await session.execute(
            select(column).where(UserPreferences.user_id == user_id)
        )
    ).scalar_one_or_none()
    return default if value is None else bool(value)


async def filter_wanting(
    session,
    user_ids: list[str],
    column: InstrumentedAttribute,
    *,
    default: bool = True,
) -> list[str]:
    """Subset of `user_ids` that have the given `notif_*` preference enabled,
    preserving order. Users with no preferences row fall back to `default`."""
    if not user_ids:
        return []
    rows = dict(
        (
            await session.execute(
                select(UserPreferences.user_id, column).where(
                    UserPreferences.user_id.in_(user_ids)
                )
            )
        ).all()
    )
    return [uid for uid in user_ids if bool(rows.get(uid, default))]
