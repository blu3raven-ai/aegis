"""Per-user preference endpoints: theme, timezone (and later notifications).

Mounted under /api/v1/settings/{profile,notifications}/*. SessionAuthMiddleware
has attached request.state.user — we never look up the row by external input.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from src.db.helpers import run_db
from src.db.models import UserPreferences
from src.settings.schemas import NotificationSettingsRequest, ProfileSettingsRequest

preferences_router = APIRouter(tags=["preferences"])


def _api_error(message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


def _require_user_id(request: Request) -> str:
    user = getattr(request.state, "user", None)
    if user is None or not getattr(user, "id", None):
        raise _api_error("unauthorized", 401)
    return str(user.id)


async def _get_or_create(session, user_id: str) -> UserPreferences:
    row = await session.get(UserPreferences, user_id)
    if row is None:
        row = UserPreferences(user_id=user_id)
        session.add(row)
        await session.flush()
    return row


@preferences_router.get("/api/v1/settings/profile")
def get_profile(request: Request) -> JSONResponse:
    user_id = _require_user_id(request)

    async def _q(session):
        row = await _get_or_create(session, user_id)
        return {"theme": row.theme, "timezone": row.timezone}

    return JSONResponse(run_db(_q), status_code=200)


@preferences_router.patch("/api/v1/settings/profile")
def patch_profile(request: Request, body: ProfileSettingsRequest) -> JSONResponse:
    user_id = _require_user_id(request)

    async def _q(session):
        row = await _get_or_create(session, user_id)
        if body.theme is not None:
            row.theme = body.theme
        if body.timezone is not None:
            row.timezone = body.timezone
        return {"theme": row.theme, "timezone": row.timezone}

    return JSONResponse(run_db(_q), status_code=200)


def _serialize_notifications(row) -> dict:
    return {
        "assignments": row.notif_assignments,
        "mentions": row.notif_mentions,
        "kev": row.notif_kev,
        "weeklyDigest": row.notif_weekly_digest,
        "marketing": row.notif_marketing,
    }


@preferences_router.get("/api/v1/settings/notifications")
def get_notifications(request: Request) -> JSONResponse:
    user_id = _require_user_id(request)

    async def _q(session):
        row = await _get_or_create(session, user_id)
        return _serialize_notifications(row)

    return JSONResponse(run_db(_q), status_code=200)


@preferences_router.patch("/api/v1/settings/notifications")
def patch_notifications(request: Request, body: NotificationSettingsRequest) -> JSONResponse:
    user_id = _require_user_id(request)

    async def _q(session):
        row = await _get_or_create(session, user_id)
        if body.assignments is not None:
            row.notif_assignments = body.assignments
        if body.mentions is not None:
            row.notif_mentions = body.mentions
        if body.kev is not None:
            row.notif_kev = body.kev
        if body.weeklyDigest is not None:
            row.notif_weekly_digest = body.weeklyDigest
        if body.marketing is not None:
            row.notif_marketing = body.marketing
        return _serialize_notifications(row)

    return JSONResponse(run_db(_q), status_code=200)
