"""REST endpoints for saved views. Per-user scoped — `actor_user_id` is the
sole authorization predicate. No admin override; admins don't get to see other
users' personal triage views."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from src.db.engine import get_session
from src.saved_views.service import (
    SavedViewIn,
    create_view,
    delete_view,
    list_views,
    set_default,
    update_view,
)
from src.settings.team_access import actor_user_id

router = APIRouter(prefix="/api/v1/saved-views", tags=["saved-views"])


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


@router.get("")
async def list_views_endpoint(
    request: Request,
    surface: str = Query(...),
) -> list[dict[str, Any]]:
    user_id = _require_user(request)
    async with get_session() as session:
        try:
            rows = await list_views(user_id=user_id, surface=surface, session=session)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [_row_to_dict(r) for r in rows]


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
