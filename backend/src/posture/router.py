"""REST endpoints for /api/v1/posture."""
from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Query, Request

from src.posture.models import (
    PostureByTeamResponse,
    PostureSnapshotResponse,
    PostureTrendResponse,
    TeamPostureItem,
    TrendPoint,
)
from src.posture.service import (
    get_posture_by_team,
    get_posture_snapshot,
    get_posture_trend,
)
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request as _resolve_asset_ids

router = APIRouter(prefix="/api/v1/posture", tags=["posture"])


@router.get("/snapshot", response_model=PostureSnapshotResponse, summary="Current posture snapshot")
async def get_snapshot(request: Request) -> PostureSnapshotResponse:
    require_permission(request, "view_findings")
    asset_ids = await _resolve_asset_ids(request)
    payload = get_posture_snapshot(asset_ids=asset_ids)
    return PostureSnapshotResponse(**asdict(payload))


@router.get("/by-team", response_model=PostureByTeamResponse, summary="Posture breakdown by team")
async def get_by_team(request: Request) -> PostureByTeamResponse:
    require_permission(request, "view_findings")
    asset_ids = await _resolve_asset_ids(request)
    org: str = getattr(request.state, "user_org", None) or request.query_params.get("org_id") or "default"
    teams_data = get_posture_by_team(asset_ids=asset_ids)
    return PostureByTeamResponse(
        teams=[TeamPostureItem(**t) for t in teams_data],
        org=org,
    )


@router.get("/trend", response_model=PostureTrendResponse, summary="Posture trend over time")
async def get_trend(
    request: Request,
    days: int = Query(90, ge=7, le=365, description="Lookback window in days"),
) -> PostureTrendResponse:
    require_permission(request, "view_findings")
    asset_ids = await _resolve_asset_ids(request)
    points = get_posture_trend(asset_ids=asset_ids, days=days)
    return PostureTrendResponse(
        points=[TrendPoint(**p) for p in points],
        days=days,
    )
