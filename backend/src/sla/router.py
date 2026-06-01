"""REST endpoints for SLA policy management and breach summary (Phase 47).

All write endpoints require the manage_settings permission.
Read endpoints (GET) are available to any authenticated user so dashboards
and read-only roles can fetch breach data.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.settings.router import require_permission
from src.sla.policy import VALID_SEVERITIES
from src.sla.service import get_sla_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["sla"])


# ── Request schemas ────────────────────────────────────────────────────────────


class UpdatePolicyRequest(BaseModel):
    deadline_days: int
    enabled: bool = True


# ── Policy endpoints ───────────────────────────────────────────────────────────


@router.get("/sla-policies")
def list_sla_policies(request: Request, org_id: str) -> dict:
    """Return all four severity policies for an org (with defaults for missing rows)."""
    service = get_sla_service()
    policies = service.get_policies(org_id)
    return {"policies": policies}


@router.put("/sla-policies/{severity}")
def update_sla_policy(request: Request, severity: str, org_id: str, body: UpdatePolicyRequest) -> dict:
    """Upsert deadline_days and enabled flag for the given severity."""
    require_permission(request, "manage_settings")

    if severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"severity must be one of {sorted(VALID_SEVERITIES)}")
    if body.deadline_days <= 0:
        raise HTTPException(status_code=422, detail="deadline_days must be greater than 0")

    service = get_sla_service()
    try:
        policy = service.update_policy(org_id, severity, body.deadline_days, body.enabled)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    return {"policy": policy}


# ── Breach summary endpoint ───────────────────────────────────────────────────


@router.get("/sla/breach-summary")
def get_breach_summary(request: Request, org_id: str) -> dict:
    """Return per-severity breach counts for the dashboard widget."""
    service = get_sla_service()
    summary = service.get_breach_summary(org_id)
    return {"summary": summary}


# ── Admin recompute endpoint ──────────────────────────────────────────────────


@router.post("/sla/recompute")
def trigger_recompute(request: Request, org_id: str) -> dict:
    """Manually trigger an SLA status recompute for the org (admin action)."""
    require_permission(request, "manage_settings")

    service = get_sla_service()
    count = service.recompute_org(org_id)
    return {"ok": True, "updated": count}
