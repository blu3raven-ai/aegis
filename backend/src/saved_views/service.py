"""Saved views service — per-user CRUD with default-uniqueness enforcement.

`saved_views.surface` is the area of the app a view applies to. For now only
`"findings"` is supported. Adding more surfaces is a code change so we can
review the URL-state schema for each.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import SavedView

KNOWN_SURFACES = frozenset({"findings"})

# Maximum url_state JSON size in bytes after serialisation. A hostile caller
# can't blow up the row beyond this.
MAX_URL_STATE_BYTES = 8 * 1024


@dataclass
class SavedViewIn:
    surface: str
    name: str
    url_state: dict[str, Any]


def _validate(payload: SavedViewIn) -> None:
    if payload.surface not in KNOWN_SURFACES:
        raise ValueError(f"unknown surface: {payload.surface}")
    if not payload.name or len(payload.name) > 255:
        raise ValueError("name must be 1-255 chars")
    if not isinstance(payload.url_state, dict):
        raise ValueError("url_state must be an object")
    if len(json.dumps(payload.url_state)) > MAX_URL_STATE_BYTES:
        raise ValueError("url_state too large")


async def create_view(*, user_id: str, payload: SavedViewIn, session: AsyncSession) -> SavedView:
    _validate(payload)
    row = SavedView(
        id=str(uuid.uuid4()),
        user_id=user_id,
        surface=payload.surface,
        name=payload.name,
        url_state=payload.url_state,
        is_default=False,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_views(*, user_id: str, surface: str, session: AsyncSession) -> list[SavedView]:
    if surface not in KNOWN_SURFACES:
        raise ValueError(f"unknown surface: {surface}")
    result = await session.execute(
        select(SavedView)
        .where(SavedView.user_id == user_id, SavedView.surface == surface)
        .order_by(SavedView.created_at.asc())
    )
    return list(result.scalars().all())


async def update_view(
    *,
    user_id: str,
    view_id: str,
    name: str | None = None,
    url_state: dict | None = None,
    session: AsyncSession,
) -> SavedView:
    row = await _get_owned(user_id, view_id, session)
    if name is not None:
        if not name or len(name) > 255:
            raise ValueError("name must be 1-255 chars")
        row.name = name
    if url_state is not None:
        if not isinstance(url_state, dict):
            raise ValueError("url_state must be an object")
        if len(json.dumps(url_state)) > MAX_URL_STATE_BYTES:
            raise ValueError("url_state too large")
        row.url_state = url_state
    await session.commit()
    await session.refresh(row)
    return row


async def delete_view(*, user_id: str, view_id: str, session: AsyncSession) -> None:
    row = await _get_owned(user_id, view_id, session)
    await session.delete(row)
    await session.commit()


async def set_default(*, user_id: str, view_id: str, session: AsyncSession) -> SavedView:
    row = await _get_owned(user_id, view_id, session)
    # Clear default on every other view in the same (user, surface) group, then mark this one.
    await session.execute(
        update(SavedView)
        .where(
            SavedView.user_id == user_id,
            SavedView.surface == row.surface,
            SavedView.id != row.id,
        )
        .values(is_default=False)
    )
    row.is_default = True
    await session.commit()
    await session.refresh(row)
    return row


async def _get_owned(user_id: str, view_id: str, session: AsyncSession) -> SavedView:
    result = await session.execute(
        select(SavedView).where(SavedView.id == view_id, SavedView.user_id == user_id)
    )
    row = result.scalars().first()
    if row is None:
        raise LookupError("saved view not found")
    return row
