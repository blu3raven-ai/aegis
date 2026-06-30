"""REST API for the per-org Argus verification connection."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.audit_log.recorder import ActorInfo, get_recorder
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.db.helpers import run_db
from src.settings.argus.service import (
    ArgusAuthError,
    delete_argus_connection,
    fetch_argus_connection,
    mint_argus_access_token,
    upsert_argus_connection,
)

_DEFAULT_ORG_ID = "default"


def _resolve_org_id() -> str:
    return _DEFAULT_ORG_ID


router = APIRouter(prefix="/api/v1/settings/argus", tags=["settings"])


class ArgusConnectionBody(BaseModel):
    endpoint: str = Field(..., min_length=4, max_length=512)
    token_endpoint: str = Field(..., min_length=4, max_length=512)
    client_id: str = Field(..., min_length=1, max_length=255)
    refresh_token: str = Field(..., min_length=1, max_length=2048)
    enabled: bool = False


@router.get("")
def get_argus_connection(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id()
    conn = run_db(lambda session: fetch_argus_connection(session, org_id))
    if conn is None:
        return {"endpoint": "", "token_endpoint": "", "client_id": "", "enabled": False, "connected": False}
    return {
        "endpoint": conn.endpoint,
        "token_endpoint": conn.token_endpoint,
        "client_id": conn.client_id,
        "enabled": conn.enabled,
        "connected": bool(conn.endpoint) and conn.enabled,
    }


@router.put("")
def put_argus_connection(
    body: ArgusConnectionBody,
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id()

    async def _q(session: AsyncSession):
        return await upsert_argus_connection(
            session,
            org_id,
            endpoint=body.endpoint,
            token_endpoint=body.token_endpoint,
            client_id=body.client_id,
            refresh_token=body.refresh_token,
            enabled=body.enabled,
        )

    conn = run_db(_q)
    get_recorder().record(
        action="argus_connection.updated",
        resource_type="argus_connection",
        resource_id=org_id,
        actor=ActorInfo(user_id="system"),
        metadata={"enabled": body.enabled, "endpoint": body.endpoint},
    )
    return {
        "endpoint": conn.endpoint,
        "token_endpoint": conn.token_endpoint,
        "client_id": conn.client_id,
        "enabled": conn.enabled,
        "connected": bool(conn.endpoint) and conn.enabled,
    }


@router.post("/test")
def test_argus_connection(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Mint an access token, then ping the Argus endpoint to confirm the connection works."""
    org_id = _resolve_org_id()
    conn = run_db(lambda session: fetch_argus_connection(session, org_id))
    if conn is None:
        raise HTTPException(status_code=404, detail="argus_connection_not_set")

    # Minting proves the OAuth exchange works without ever exposing the token.
    try:
        access_token = mint_argus_access_token(conn)
    except ArgusAuthError as exc:
        return {"ok": False, "error": "auth_failed", "detail": str(exc)[:200]}

    import httpx
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.get(
                f"{conn.endpoint.rstrip('/')}/health",
                headers={"Authorization": f"Bearer {access_token}"},
            )
    except httpx.RequestError as exc:
        return {"ok": False, "error": "network", "detail": str(exc)[:200]}

    if resp.status_code in (200, 201, 204):
        return {"ok": True}
    return {
        "ok": False,
        "error": f"http_{resp.status_code}",
        "detail": resp.text[:200],
    }


@router.delete("")
def delete_argus_connection_route(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id()
    deleted = run_db(lambda session: delete_argus_connection(session, org_id))
    if not deleted:
        raise HTTPException(status_code=404, detail="argus_connection_not_set")
    get_recorder().record(
        action="argus_connection.deleted",
        resource_type="argus_connection",
        resource_id=org_id,
        actor=ActorInfo(user_id="system"),
    )
    return {"deleted": True}
