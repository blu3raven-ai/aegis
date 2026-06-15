"""Org-wide settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import OrgSettings
from src.settings.router import require_permission
from src.settings.schemas import OrgLogoRequest, OrgSettingsRequest

org_settings_router = APIRouter(prefix="/api/v1/settings/org", tags=["org-settings"])


_MAX_LOGO_DATA_URL_BYTES = 200 * 1024  # ~100KB image + base64 expansion
_ALLOWED_LOGO_MIME = ("image/png", "image/jpeg", "image/svg+xml", "image/webp")


def _api_error(message: str, status_code: int) -> HTTPException:
    return HTTPException(status_code=status_code, detail=message)


def _validate_logo_data_url(data_url: str) -> None:
    if len(data_url) > _MAX_LOGO_DATA_URL_BYTES:
        raise _api_error("Logo too large.", 400)
    if not data_url.startswith("data:"):
        raise _api_error("Logo must be a data URL.", 400)
    header, _, _ = data_url.partition(",")
    if ";base64" not in header:
        raise _api_error("Logo must be base64-encoded.", 400)
    mime = header.removeprefix("data:").split(";", 1)[0].strip().lower()
    if mime not in _ALLOWED_LOGO_MIME:
        raise _api_error("Unsupported image type.", 400)


def _serialize(row: OrgSettings) -> dict:
    return {
        "name": row.name,
        "logoDataUrl": row.logo_data_url,
        "updatedAt": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _get_or_create_singleton(session) -> OrgSettings:
    row = (await session.execute(select(OrgSettings).where(OrgSettings.id == 1))).scalar_one_or_none()
    if row is None:
        row = OrgSettings(id=1)
        session.add(row)
        await session.flush()
    return row


@org_settings_router.get("")
def get_org_settings(request: Request) -> JSONResponse:
    async def _q(session):
        row = await _get_or_create_singleton(session)
        return _serialize(row)

    return JSONResponse(run_db(_q), status_code=200)


@org_settings_router.patch("")
def patch_org_settings(request: Request, body: OrgSettingsRequest) -> JSONResponse:
    require_permission(request, "manage_organisations")

    async def _q(session):
        row = await _get_or_create_singleton(session)
        if body.name is not None:
            row.name = body.name.strip() or None
        return _serialize(row)

    return JSONResponse(run_db(_q), status_code=200)


@org_settings_router.post("/logo")
def set_org_logo(request: Request, body: OrgLogoRequest) -> JSONResponse:
    require_permission(request, "manage_organisations")
    _validate_logo_data_url(body.dataUrl)

    async def _q(session):
        row = await _get_or_create_singleton(session)
        row.logo_data_url = body.dataUrl
        return _serialize(row)

    return JSONResponse(run_db(_q), status_code=200)


@org_settings_router.delete("/logo")
def clear_org_logo(request: Request) -> JSONResponse:
    require_permission(request, "manage_organisations")

    async def _q(session):
        row = await _get_or_create_singleton(session)
        row.logo_data_url = None
        return _serialize(row)

    return JSONResponse(run_db(_q), status_code=200)
