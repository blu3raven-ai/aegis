"""GraphQL resolver for the saved-views surface.

Mirrors GET /api/v1/settings/saved-views. Per-user scoped — ``actor_user_id`` is the
sole authorization predicate; no admin override (matches the REST contract).
The service raises ``ValueError`` on an unknown surface; we surface that as
a coded ``VALIDATION_ERROR`` so the masking extension passes it through.
"""
from __future__ import annotations

from typing import Optional

import strawberry
from graphql import GraphQLError

from src.authz.teams.access import actor_user_id
from src.db.helpers import run_db
from src.settings.saved_views.service import list_views


@strawberry.type
class SavedView:
    id: str
    surface: str
    name: str
    url_state: strawberry.scalars.JSON
    is_default: bool
    created_at: Optional[str]
    updated_at: Optional[str]


def _row_to_type(row) -> SavedView:
    return SavedView(
        id=row.id,
        surface=row.surface,
        name=row.name,
        url_state=row.url_state,
        is_default=row.is_default,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


def saved_views(*, info_context: dict, surface: str) -> list[SavedView]:
    request = info_context.get("request") if info_context else None
    if request is None:
        raise GraphQLError(
            "Unauthorized",
            extensions={"code": "UNAUTHENTICATED"},
        )

    user_id = actor_user_id(request)
    if not user_id:
        raise GraphQLError(
            "Unauthorized",
            extensions={"code": "UNAUTHENTICATED"},
        )

    async def _query(session):
        return await list_views(user_id=user_id, surface=surface, session=session)

    try:
        rows = run_db(_query)
    except ValueError as exc:
        raise GraphQLError(
            str(exc),
            extensions={"code": "VALIDATION_ERROR"},
        ) from exc

    return [_row_to_type(r) for r in rows]
