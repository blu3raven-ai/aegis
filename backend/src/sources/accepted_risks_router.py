"""REST for maintainer-declared accepted-risk carve-outs (source configuration)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import MANAGE_SOURCES
from src.authz.teams.access import actor_user_id
from src.db.engine import get_session
from src.sources import accepted_risks_service as svc

router = APIRouter(prefix="/api/v1/accepted-risks", tags=["sources"])


class AcceptedRiskCreate(BaseModel):
    asset_id: str | None = None
    source_connection_id: str | None = None
    statement: str
    path_glob: str | None = None
    rule_id: str | None = None
    scanner: str | None = None
    enabled: bool = True


class AcceptedRiskPatch(BaseModel):
    statement: str | None = None
    path_glob: str | None = None
    rule_id: str | None = None
    scanner: str | None = None
    enabled: bool | None = None


@router.get("")
async def list_accepted_risks(
    request: Request, _: None = Depends(Permission(MANAGE_SOURCES))
) -> dict:
    asset_ids = await resolve_asset_ids_from_request(request)
    if not asset_ids:
        return {"acceptedRisks": []}
    async with get_session() as session:
        return {"acceptedRisks": await svc.list_for_assets(session, asset_ids)}


@router.post("")
async def create_accepted_risk(
    request: Request,
    body: AcceptedRiskCreate,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> dict:
    asset_ids = await resolve_asset_ids_from_request(request)
    if body.asset_id is not None and body.asset_id not in asset_ids:
        raise HTTPException(status_code=404, detail="Asset not found")
    async with get_session() as session:
        created = await svc.create(
            session, body.model_dump(), created_by=actor_user_id(request)
        )
    return {"acceptedRisk": created}


@router.patch("/{risk_id}")
async def update_accepted_risk(
    request: Request,
    risk_id: int,
    body: AcceptedRiskPatch,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> dict:
    asset_ids = await resolve_asset_ids_from_request(request)
    async with get_session() as session:
        row = await svc.get_scoped(session, risk_id, asset_ids)
        if row is None:
            raise HTTPException(status_code=404, detail="Accepted risk not found")
        updated = await svc.update_fields(session, row, body.model_dump(exclude_unset=True))
    return {"acceptedRisk": updated}


@router.delete("/{risk_id}")
async def delete_accepted_risk(
    request: Request,
    risk_id: int,
    _: None = Depends(Permission(MANAGE_SOURCES)),
) -> dict:
    asset_ids = await resolve_asset_ids_from_request(request)
    async with get_session() as session:
        row = await svc.get_scoped(session, risk_id, asset_ids)
        if row is None:
            raise HTTPException(status_code=404, detail="Accepted risk not found")
        await svc.delete(session, row)
    return {"deleted": True}
