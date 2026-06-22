"""REST endpoints for SLA policy management and breach summary."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import MANAGE_SETTINGS, VIEW_FINDINGS, VIEW_SETTINGS
from src.sla.policy import VALID_SEVERITIES
from src.sla.service import get_sla_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla", tags=["sla"])


class UpdatePolicyRequest(BaseModel):
    deadline_days: int
    enabled: bool = True


@router.get("/policies")
def list_sla_policies(
    request: Request,
    _: None = Depends(Permission(VIEW_SETTINGS)),
) -> dict:
    """Return all four severity policies (with defaults for missing rows).

    Gated on VIEW_SETTINGS — SLA policy is a settings surface, parity with
    the PUT next door (manage_settings, which implies view_settings).
    """
    service = get_sla_service()
    policies = service.get_policies()
    return {"policies": policies}


@router.put("/policies/{severity}")
def update_sla_policy(
    request: Request,
    severity: str,
    body: UpdatePolicyRequest,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Upsert deadline_days and enabled flag for the given severity."""
    if severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of {sorted(VALID_SEVERITIES)}")
    if body.deadline_days <= 0:
        raise HTTPException(status_code=422, detail="deadline_days must be greater than 0")

    service = get_sla_service()
    try:
        policy = service.update_policy(severity, body.deadline_days, body.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {"policy": policy}


@router.get("/breach-summary")
async def get_breach_summary(
    request: Request,
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> dict:
    """Return per-severity breach counts scoped to the caller's assets.

    Gated on VIEW_FINDINGS since the response is a findings rollup; the
    asset-scope filter already prevents cross-tenant counts. Without this
    gate any session could read aggregate breach counts for their own
    assets — minor but unintended.
    """
    asset_ids = await resolve_asset_ids_from_request(request)
    service = get_sla_service()
    summary = service.get_breach_summary(asset_ids=asset_ids)
    return {"summary": summary}


@router.post("/recompute")
async def trigger_recompute(
    request: Request,
    _: None = Depends(Permission(MANAGE_SETTINGS)),
) -> dict:
    """Manually trigger an SLA status recompute over the caller's assets."""
    asset_ids = await resolve_asset_ids_from_request(request)
    service = get_sla_service()
    count = service.recompute(asset_ids=asset_ids)
    return {"ok": True, "updated": count}
