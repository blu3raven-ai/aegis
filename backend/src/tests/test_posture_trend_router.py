"""Smoke tests for GET /api/v1/posture/trend."""
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


def test_trend_happy_path_empty():
    """Empty result when no snapshots exist — valid, not an error."""
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.posture.router._resolve_asset_ids", new=AsyncMock(return_value=[])),
        patch("src.posture.router.get_posture_trend", return_value=[]),
    ):
        resp = TestClient(app).get("/api/v1/posture/trend?days=30")
    assert resp.status_code == 200
    body = resp.json()
    assert body["days"] == 30
    assert body["points"] == []


def test_trend_happy_path_with_data():
    fake_points = [
        {"date": "2026-06-01", "risk_score": 72, "critical": 2, "high": 5, "medium": 3, "low": 1, "total": 11},
        {"date": "2026-06-02", "risk_score": 68, "critical": 1, "high": 4, "medium": 3, "low": 1, "total": 9},
    ]
    app = _make_app()
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.posture.router._resolve_asset_ids", new=AsyncMock(return_value=["a-1"])),
        patch("src.posture.router.get_posture_trend", return_value=fake_points),
    ):
        resp = TestClient(app).get("/api/v1/posture/trend?days=7")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["points"]) == 2
    assert body["points"][0]["risk_score"] == 72
    assert body["points"][1]["date"] == "2026-06-02"


def test_trend_unauthenticated():
    app = _make_app(with_user=False)
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/trend")
    assert resp.status_code in (401, 403)


def test_trend_missing_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/trend")
    assert resp.status_code == 403
