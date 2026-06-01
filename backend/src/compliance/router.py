"""REST endpoints for compliance framework mapping."""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from src.compliance.models import FrameworkControlSchema
from src.compliance.service import (
    SUPPORTED_FRAMEWORKS,
    FRAMEWORK_LABELS,
    get_controls_for_finding,
    get_findings_for_control,
    get_framework_summary,
    list_controls_for_framework,
    list_frameworks,
)
from src.db.helpers import run_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/compliance", tags=["compliance"])


@router.get("/frameworks")
async def get_frameworks() -> list[dict[str, str]]:
    """List supported compliance frameworks."""
    return await list_frameworks()


@router.get("/frameworks/{framework}/controls")
def get_controls(framework: str) -> list[dict[str, Any]]:
    """List all controls in a given framework."""
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")

    async def _query(session):
        rows = await list_controls_for_framework(session, framework)
        return [FrameworkControlSchema.model_validate(r).model_dump() for r in rows]

    return run_db(_query)


@router.get("/frameworks/{framework}/summary")
def get_summary(framework: str, org_id: str) -> dict[str, Any]:
    """Return per-control finding counts for an org in a framework."""
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")

    async def _query(session):
        items = await get_framework_summary(session, framework, org_id)
        return {
            "framework": framework,
            "label": FRAMEWORK_LABELS[framework],
            "controls": [item.model_dump() for item in items],
        }

    return run_db(_query)


@router.get("/controls/{framework}/{control_id}/findings")
def get_findings_by_control(framework: str, control_id: str, org_id: str) -> dict[str, Any]:
    """Return open findings mapped to a specific control for an org."""
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(status_code=404, detail=f"Unknown framework: {framework}")

    async def _query(session):
        briefs = await get_findings_for_control(session, framework, control_id, org_id)
        return {
            "framework": framework,
            "control_id": control_id,
            "findings": [b.model_dump() for b in briefs],
        }

    return run_db(_query)


@router.get("/findings/{finding_id}/controls")
def get_controls_for_finding_endpoint(finding_id: int) -> dict[str, Any]:
    """Return all compliance controls a finding violates."""
    async def _query(session):
        return await get_controls_for_finding(session, finding_id)

    mappings = run_db(_query)
    return {"finding_id": finding_id, "controls": mappings}
