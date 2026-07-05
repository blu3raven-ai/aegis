"""API key management routes."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.auth.credentials import service
from src.audit_log.decorators import audited
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS

router = APIRouter(prefix="/api/v1/auth/api-keys", tags=["auth"])


class CreateApiKeyRequest(BaseModel):
    name: str
    scopes: list[str] = []
    expires_in_days: int | None = None


@router.get("")
async def list_api_keys(_: None = Depends(Permission(MANAGE_SETTINGS))) -> dict:
    keys = await service.list_keys()
    return {"keys": [k.to_dict() for k in keys]}


@router.post("", status_code=201)
@audited(action="api_key.created", resource_type="api_key")
async def create_api_key(
    request: Request,
    body: CreateApiKeyRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    created_by = getattr(request.state, "user_sub", None)
    record, token = await service.create(
        name=body.name,
        scopes=body.scopes,
        created_by=created_by,
        expires_in_days=body.expires_in_days,
    )
    result = record.to_dict()
    # Token returned exactly once — never stored or logged
    result["token"] = token
    return result


@router.delete("/{key_id}")
@audited(action="api_key.revoked", resource_type="api_key", resource_id_param="key_id")
async def revoke_api_key(
    request: Request,
    key_id: int,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    record = await service.revoke(key_id)
    if record is None:
        raise HTTPException(status_code=404, detail="api key not found")
    return record.to_dict()
