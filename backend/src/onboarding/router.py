"""REST endpoints for the onboarding wizard.

GET  /api/v1/onboarding/state            — fetch current wizard state for org
POST /api/v1/onboarding/state/step/{id}  — advance/skip/dismiss a step
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from src.onboarding.models import STEP_ORDER, StepId
from src.onboarding.service import complete_step, dismiss, get_state, skip_step
from src.settings.router import require_permission

router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"])


class StepActionRequest(BaseModel):
    action: Literal["complete", "skip", "dismiss"]
    data: dict[str, Any] = {}


@router.get("/state")
def get_onboarding_state(request: Request, org_id: str) -> dict:
    require_permission(request, "manage_settings")
    state = get_state(org_id)
    return {"state": state.model_dump()}


@router.post("/state/step/{step_id}")
def update_step(
    request: Request,
    step_id: str,
    body: StepActionRequest,
    org_id: str,
) -> dict:
    require_permission(request, "manage_settings")

    if step_id not in STEP_ORDER:
        raise HTTPException(status_code=404, detail=f"unknown step: {step_id}")

    sid: StepId = step_id  # type: ignore[assignment]

    if body.action == "complete":
        state = complete_step(org_id, sid, body.data)
    elif body.action == "skip":
        state = skip_step(org_id, sid)
    elif body.action == "dismiss":
        state = dismiss(org_id)
    else:
        raise HTTPException(status_code=422, detail=f"invalid action: {body.action}")

    return {"state": state.model_dump()}
