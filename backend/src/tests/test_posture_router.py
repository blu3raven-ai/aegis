"""Smoke tests for /api/v1/posture/snapshot — endpoint shape + auth.

Mocks the service to avoid DB dependency.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.posture.router import router as posture_router  # noqa: E402
from src.shared.analytics import (  # noqa: E402
    AnalyticsPayload,
    Counts,
    RemediationMetrics,
    RepositoryCoverage,
    RiskScore,
)

_VIEWER_PERMS = {"view_findings"}


def _make_app(*, with_user: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(posture_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "admin-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    return app


def _fake_payload() -> AnalyticsPayload:
    return AnalyticsPayload(
        counts=Counts(total=10, critical=1, high=2, medium=3, low=4),
        severityDistribution=[],
        ageBuckets=[],
        topRepositories=[],
        remediation=RemediationMetrics(totalFixed=5, avgDays=7.5, medianDays=6.0, fixedLast30d=3),
        repositoryCoverage=RepositoryCoverage(total=4, affected=2, unaffected=2, percentage=50),
        riskScore=RiskScore(score=30, rating="Moderate", summary="Some critical/high present."),
    )


def _empty_payload() -> AnalyticsPayload:
    return AnalyticsPayload(
        counts=Counts(total=0, critical=0, high=0, medium=0, low=0),
        severityDistribution=[],
        ageBuckets=[],
        topRepositories=[],
        remediation=RemediationMetrics(totalFixed=0, avgDays=None, medianDays=None, fixedLast30d=0),
        repositoryCoverage=RepositoryCoverage(total=0, affected=0, unaffected=0, percentage=0),
        riskScore=RiskScore(score=0, rating="Low", summary="Overall exposure is relatively contained right now."),
    )


def test_snapshot_happy_path():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.posture.router._resolve_asset_ids", new=AsyncMock(return_value=["a-1"])), \
         patch("src.posture.router.get_posture_snapshot", return_value=_fake_payload()):
        resp = TestClient(app).get("/api/v1/posture/snapshot")

    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["total"] == 10
    assert body["counts"]["critical"] == 1
    assert body["riskScore"]["score"] == 30
    assert body["repositoryCoverage"]["percentage"] == 50


def test_snapshot_empty_org():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.posture.router.get_posture_snapshot", return_value=_empty_payload()):
        resp = TestClient(app).get("/api/v1/posture/snapshot")

    assert resp.status_code == 200
    body = resp.json()
    assert body["counts"]["total"] == 0
    assert body["riskScore"]["rating"] == "Low"


def test_snapshot_unauthenticated():
    # No user state injected; _resolve_effective_permissions patched to return
    # empty set so it doesn't attempt a real DB lookup — the 403 from
    # require_permission is the expected auth rejection.
    app = _make_app(with_user=False)
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/snapshot")
    assert resp.status_code in (401, 403)


def test_snapshot_missing_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/posture/snapshot")
    assert resp.status_code == 403
