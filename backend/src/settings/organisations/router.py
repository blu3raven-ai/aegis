"""REST endpoints for organisation settings.

Public read is unauthenticated (listed in session_gate.PUBLIC_PATHS).
Mutations (update name, set/clear logo) require MANAGE_ORGANISATIONS.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_ORGANISATIONS
from src.db.helpers import run_db
from src.db.models import OrgSettings
from src.shared.branding_validation import validate_logo_data_url
from sqlalchemy import select

router = APIRouter(prefix="/api/v1/settings/organisations", tags=["settings"])


def _iso_or_none(value):
    return value.isoformat() if value is not None else None


async def _read_branding(session) -> dict:
    row = (await session.execute(
        select(OrgSettings).where(OrgSettings.id == 1)
    )).scalar_one_or_none()
    if row is None:
        return {"name": None, "logoDataUrl": None, "updatedAt": None}
    return {"name": row.name, "logoDataUrl": row.logo_data_url, "updatedAt": _iso_or_none(row.updated_at)}


async def _get_or_create_singleton(session) -> OrgSettings:
    row = (await session.execute(
        select(OrgSettings).where(OrgSettings.id == 1)
    )).scalar_one_or_none()
    if row is None:
        row = OrgSettings(id=1)
        session.add(row)
        await session.flush()
    return row


def _row_to_dict(row: OrgSettings) -> dict:
    return {"name": row.name, "logoDataUrl": row.logo_data_url, "updatedAt": _iso_or_none(row.updated_at)}


@router.get("/branding")
def get_org_branding() -> JSONResponse:
    """Return organisation name and logo. Unauthenticated — used for pre-login branding."""
    data = run_db(_read_branding)
    return JSONResponse(data)


class UpdateOrgNameBody(BaseModel):
    name: Optional[str] = None


@router.patch("")
def update_org_name(
    request: Request,
    body: UpdateOrgNameBody,
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> JSONResponse:
    """Update the organisation display name. Requires MANAGE_ORGANISATIONS."""
    async def _q(session):
        row = await _get_or_create_singleton(session)
        row.name = (body.name.strip() or None) if body.name is not None else None
        return _row_to_dict(row)

    data = run_db(_q)
    return JSONResponse(data)


class SetLogoBody(BaseModel):
    dataUrl: str


@router.put("/logo")
def set_org_logo(
    request: Request,
    body: SetLogoBody,
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> JSONResponse:
    """Store a new organisation logo. Requires MANAGE_ORGANISATIONS."""
    error = validate_logo_data_url(body.dataUrl)
    if error:
        raise HTTPException(status_code=400, detail=error)

    async def _q(session):
        row = await _get_or_create_singleton(session)
        row.logo_data_url = body.dataUrl
        return _row_to_dict(row)

    data = run_db(_q)
    return JSONResponse(data)


@router.delete("/logo")
def clear_org_logo(
    request: Request,
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> JSONResponse:
    """Clear the organisation logo. Requires MANAGE_ORGANISATIONS."""
    async def _q(session):
        row = await _get_or_create_singleton(session)
        row.logo_data_url = None
        return _row_to_dict(row)

    data = run_db(_q)
    return JSONResponse(data)
