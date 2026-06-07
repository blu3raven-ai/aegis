"""Smoke tests for GET /api/v1/posture/by-team."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.posture.router import router as posture_router  # noqa: E402

_VIEWER_PERMS = {"view_findings"}


def _make_app(*, with_user: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(posture_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "test-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    return app


def test_by_team_empty():
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.posture.router._resolve_asset_ids", new=AsyncMock(return_value=[])),
        patch("src.posture.router.get_posture_by_team", return_value=[]),
    ):
        resp = TestClient(app).get("/api/v1/posture/by-team")
    assert resp.status_code == 200
    body = resp.json()
    assert body["org"] == "test-org"
    assert body["teams"] == []


def test_by_team_with_data():
    fake_teams = [
        {
            "team_id": "team_a",
            "team_name": "Team A",
            "repo_count": 3,
            "counts": {"total": 12, "critical": 2, "high": 5, "medium": 3, "low": 2},
            "risk_score": {"score": 75, "rating": "High", "summary": "..."},
        },
        {
            "team_id": "team_b",
            "team_name": "Team B",
            "repo_count": 1,
            "counts": {"total": 1, "critical": 0, "high": 0, "medium": 1, "low": 0},
            "risk_score": {"score": 10, "rating": "Low", "summary": "..."},
        },
    ]
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.posture.router._resolve_asset_ids", new=AsyncMock(return_value=["a-1", "a-2"])),
        patch("src.posture.router.get_posture_by_team", return_value=fake_teams),
    ):
        resp = TestClient(app).get("/api/v1/posture/by-team")
    assert resp.status_code == 200
    body = resp.json()
    teams = body["teams"]
    assert len(teams) == 2
    assert teams[0]["team_id"] == "team_a"
    assert teams[0]["risk_score"]["score"] == 75
    assert teams[0]["repo_count"] == 3


def test_by_team_unauthenticated():
    app = _make_app(with_user=False)
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/by-team")
    assert resp.status_code in (401, 403)


def test_by_team_no_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/by-team")
    assert resp.status_code == 403


def test_by_team_org_only_raises_after_plan_d():
    """After Plan D, org-only path raises ValueError; asset_ids is required."""
    import pytest
    from src.posture.service import get_posture_by_team

    with pytest.raises(ValueError, match="org-only path not supported after Plan D"):
        get_posture_by_team(org="org_x")
