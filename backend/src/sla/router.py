"""REST endpoints for SLA policy management and breach summary."""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request
from src.sla.policy import VALID_SEVERITIES
from src.sla.service import get_sla_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["sla"])


class UpdatePolicyRequest(BaseModel):
    deadline_days: int
    enabled: bool = True


@router.get("/sla-policies")
def list_sla_policies(request: Request) -> dict:
    """Return all four severity policies (with defaults for missing rows)."""
    service = get_sla_service()
    policies = service.get_policies()
    return {"policies": policies}


@router.put("/sla-policies/{severity}")
def update_sla_policy(request: Request, severity: str, body: UpdatePolicyRequest) -> dict:
    """Upsert deadline_days and enabled flag for the given severity."""
    require_permission(request, "manage_settings")

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


@router.get("/sla/breach-summary")
async def get_breach_summary(request: Request) -> dict:
    """Return per-severity breach counts scoped to the caller's assets."""
    asset_ids = await resolve_asset_ids_from_request(request)
    service = get_sla_service()
    summary = service.get_breach_summary(asset_ids=asset_ids)
    return {"summary": summary}


@router.post("/sla/recompute")
async def trigger_recompute(request: Request) -> dict:
    """Manually trigger an SLA status recompute over the caller's assets."""
    require_permission(request, "manage_settings")

    asset_ids = await resolve_asset_ids_from_request(request)
    service = get_sla_service()
    count = service.recompute(asset_ids=asset_ids)
    return {"ok": True, "updated": count}
