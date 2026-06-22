"""Admin CRUD for per-org webhook receiver secrets."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from src.audit_log.recorder import ActorInfo, get_recorder
from src.settings.webhooks.schemas import (
    WebhookEndpointCreate,
    WebhookEndpointWithSecret,
)
from src.settings.webhooks.service import (
    WebhookEndpointConflict,
    create_endpoint,
    delete_endpoint,
    rotate_endpoint,
)
from src.db.helpers import run_db
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS

router = APIRouter(prefix="/api/v1/settings/webhooks", tags=["settings"])

# Single-tenant deployment stores everything under this org_id; matches the
# llm_config convention. When the codebase grows multi-tenant the resolver
# becomes request-scoped.
_DEFAULT_ORG_ID = "default"


def _resolve_org_id(_request: Request) -> str:
    return _DEFAULT_ORG_ID


@router.post("", status_code=201, response_model=WebhookEndpointWithSecret)
def create_webhook_endpoint(
    request: Request,
    body: WebhookEndpointCreate,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id(request)

    async def _q(session):
        try:
            return await create_endpoint(session, org_id=org_id, provider=body.provider)
        except WebhookEndpointConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    payload = run_db(_q)
    get_recorder().record(
        action="webhook_endpoint.created",
        resource_type="webhook_endpoint",
        resource_id=str(payload["id"]),
        actor=ActorInfo(user_id="system"),
        metadata={"provider": body.provider},
    )
    return payload


@router.post("/{endpoint_id}/rotate", response_model=WebhookEndpointWithSecret)
def rotate_webhook_endpoint(
    request: Request,
    endpoint_id: str,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    org_id = _resolve_org_id(request)

    async def _q(session):
        return await rotate_endpoint(session, org_id=org_id, endpoint_id=endpoint_id)

    payload = run_db(_q)
    if payload is None:
        raise HTTPException(status_code=404, detail="webhook_endpoint_not_found")
    get_recorder().record(
        action="webhook_endpoint.rotated",
        resource_type="webhook_endpoint",
        resource_id=str(payload["id"]),
        actor=ActorInfo(user_id="system"),
        metadata={"provider": payload["provider"]},
    )
    return payload


@router.delete("/{endpoint_id}", status_code=204, response_model=None)
def delete_webhook_endpoint(
    request: Request,
    endpoint_id: str,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> Response:
    org_id = _resolve_org_id(request)

    async def _q(session):
        return await delete_endpoint(session, org_id=org_id, endpoint_id=endpoint_id)

    deleted = run_db(_q)
    if not deleted:
        raise HTTPException(status_code=404, detail="webhook_endpoint_not_found")
    get_recorder().record(
        action="webhook_endpoint.deleted",
        resource_type="webhook_endpoint",
        resource_id=endpoint_id,
        actor=ActorInfo(user_id="system"),
        metadata={},
    )
    return Response(status_code=204)
