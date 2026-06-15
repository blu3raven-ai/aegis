"""SCIM admin endpoints."""
from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import ScimConfig
from src.settings.router import require_permission
from src.settings.schemas import ScimConfigRequest

scim_admin_router = APIRouter(prefix="/api/v1/settings/scim", tags=["scim-admin"])


def _origin(request: Request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _serialize(row: ScimConfig, request: Request) -> dict:
    return {
        "enabled": row.enabled,
        "defaultRoleId": row.default_role_id,
        "tokenSet": row.token_hash is not None,
        "scimEndpointUrl": f"{_origin(request)}/scim/v2/",
        "updatedAt": row.updated_at.isoformat() if row.updated_at else None,
    }


async def _get_singleton(session) -> ScimConfig:
    row = (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one_or_none()
    if row is None:
        row = ScimConfig(id=1)
        session.add(row)
        await session.flush()
    return row


@scim_admin_router.get("")
def get_scim(request: Request) -> JSONResponse:
    async def _q(session):
        return _serialize(await _get_singleton(session), request)
    return JSONResponse(run_db(_q), status_code=200)


@scim_admin_router.patch("")
def patch_scim(request: Request, body: ScimConfigRequest) -> JSONResponse:
    require_permission(request, "manage_settings")

    async def _q(session):
        row = await _get_singleton(session)
        if body.enabled is not None:
            row.enabled = body.enabled
        if body.defaultRoleId is not None:
            row.default_role_id = body.defaultRoleId or None
        return _serialize(row, request)

    return JSONResponse(run_db(_q), status_code=200)


@scim_admin_router.post("/token")
def generate_scim_token(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")
    raw = secrets.token_urlsafe(32)
    hashed = _hash_token(raw)

    async def _q(session):
        row = await _get_singleton(session)
        row.token_hash = hashed
        return {"token": raw, "updatedAt": row.updated_at.isoformat()}

    return JSONResponse(run_db(_q), status_code=200)


@scim_admin_router.delete("/token")
def clear_scim_token(request: Request) -> JSONResponse:
    require_permission(request, "manage_settings")

    async def _q(session):
        row = await _get_singleton(session)
        row.token_hash = None
        return _serialize(row, request)

    return JSONResponse(run_db(_q), status_code=200)
