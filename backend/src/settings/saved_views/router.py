"""REST endpoints for saved views — mutations only. Per-user scoped:
`actor_user_id` is the sole authorization predicate, with no admin override.

The read surface (GET /api/v1/settings/saved-views) was migrated to GraphQL — see
src/graphql/saved_views_resolvers.py."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from src.db.engine import get_session
from src.settings.saved_views.service import (
    SavedViewIn,
    create_view,
    delete_view,
    set_default,
    update_view,
)
from src.authz.teams.access import actor_user_id

router = APIRouter(prefix="/api/v1/settings/saved-views", tags=["settings"])


def _require_user(request: Request) -> str:
    uid = actor_user_id(request)
    if not uid:
        raise HTTPException(status_code=401, detail="auth required")
    return uid


def _row_to_dict(row) -> dict[str, Any]:
    return {
        "id": row.id,
        "surface": row.surface,
        "name": row.name,
        "url_state": row.url_state,
        "is_default": row.is_default,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


@router.post("", status_code=201)
async def create_view_endpoint(request: Request) -> dict[str, Any]:
    user_id = _require_user(request)
    body = await request.json()
    try:
        payload = SavedViewIn(
            surface=body["surface"],
            name=body["name"],
            url_state=body.get("url_state") or {},
        )
    except KeyError as exc:
        raise HTTPException(status_code=400, detail=f"missing field: {exc.args[0]}") from exc
    async with get_session() as session:
        try:
            row = await create_view(user_id=user_id, payload=payload, session=session)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _row_to_dict(row)


@router.patch("/{view_id}")
async def update_view_endpoint(view_id: str, request: Request) -> dict[str, Any]:
    user_id = _require_user(request)
    body = await request.json()
    async with get_session() as session:
        try:
            if body.get("set_default") is True:
                row = await set_default(user_id=user_id, view_id=view_id, session=session)
                return _row_to_dict(row)
            row = await update_view(
                user_id=user_id,
                view_id=view_id,
                name=body.get("name"),
                url_state=body.get("url_state"),
                session=session,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return _row_to_dict(row)


@router.delete("/{view_id}", status_code=204)
async def delete_view_endpoint(view_id: str, request: Request) -> None:
    user_id = _require_user(request)
    async with get_session() as session:
        try:
            await delete_view(user_id=user_id, view_id=view_id, session=session)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
