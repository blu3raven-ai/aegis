"""REST endpoints for runner administration (admin-facing).

Authorization: MANAGE_RUNNERS — split out from MANAGE_SETTINGS so a
delegated ops role (e.g. on-call) can rotate tokens or revoke a runner
without also having permission to touch SSO / audit-stream / LLM /
notification config. Backwards compatible because MANAGE_SETTINGS
implies MANAGE_RUNNERS via the IMPLIED table.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from src.audit_log.decorators import audited
from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_RUNNERS
from src.runner.admin_service import (
    approve,
    generate_token,
    remove,
    revoke,
    rotate_token,
    update_settings,
)

router = APIRouter(prefix="/api/v1/runners", tags=["runners"])
_REQUIRE_MANAGE_RUNNERS = Depends(Permission(MANAGE_RUNNERS))


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class UpdateSettingsBody(BaseModel):
    maxConcurrent: Optional[int] = None
    name: Optional[str] = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/tokens")
@audited(action="runner.token.generated", resource_type="runner_registration_token")
def handle_generate_runner_token(
    request: Request, _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(content=generate_token())


@router.patch("/{runner_id}/settings")
@audited(action="runner.settings.updated", resource_type="runner",
         resource_id_param="runner_id")
def handle_update_runner_settings(
    runner_id: str,
    body: UpdateSettingsBody,
    request: Request,
    _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(
        content=update_settings(
            runner_id,
            max_concurrent=body.maxConcurrent,
            name=body.name,
        )
    )


@router.post("/{runner_id}/approve")
@audited(action="runner.approved", resource_type="runner",
         resource_id_param="runner_id")
def handle_approve_runner(
    runner_id: str, request: Request, _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(content=approve(request, runner_id))


@router.post("/{runner_id}/revoke")
@audited(action="runner.revoked", resource_type="runner",
         resource_id_param="runner_id")
def handle_revoke_runner(
    runner_id: str, request: Request, _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(content=revoke(runner_id))


@router.delete("/{runner_id}")
@audited(action="runner.deleted", resource_type="runner",
         resource_id_param="runner_id")
def handle_delete_runner(
    runner_id: str, request: Request, _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(content=remove(runner_id))


@router.post("/{runner_id}/rotate-token")
@audited(action="runner.token.rotated", resource_type="runner",
         resource_id_param="runner_id")
def handle_rotate_runner_token(
    runner_id: str, request: Request, _: None = _REQUIRE_MANAGE_RUNNERS,
) -> JSONResponse:
    return JSONResponse(content=rotate_token(runner_id))
