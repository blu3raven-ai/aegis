"""API key management routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.api_keys import service
from src.audit_log.decorators import audited
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/api-keys", tags=["api-keys"])


class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: list[str] = []
    expires_in_days: int | None = None
    org_id: str


@router.get("")
async def list_api_keys(request: Request, org_id: str) -> dict:
    require_permission(request, "manage_settings")
    keys = await service.list_keys(org_id)
    return {"keys": [k.to_dict() for k in keys]}


@audited(action="api_key.created", resource_type="api_key")
@router.post("", status_code=201)
async def create_api_key(request: Request, body: CreateApiKeyRequest) -> dict:
    require_permission(request, "manage_settings")
    created_by = getattr(request.state, "user_sub", None)
    record, token = await service.create(
        org_id=body.org_id,
        name=body.name,
        scopes=body.scopes,
        created_by=created_by,
        expires_in_days=body.expires_in_days,
    )
    result = record.to_dict()
    # Token returned exactly once — never stored or logged
    result["token"] = token
    return result


@audited(action="api_key.revoked", resource_type="api_key", resource_id_param="key_id")
@router.delete("/{key_id}")
async def revoke_api_key(request: Request, key_id: int, org_id: str) -> dict:
    require_permission(request, "manage_settings")
    record = await service.revoke(key_id, org_id)
    if record is None:
        raise HTTPException(status_code=404, detail="api key not found")
    return record.to_dict()
