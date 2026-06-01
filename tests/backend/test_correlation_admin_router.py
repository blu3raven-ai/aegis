"""Tests for the correlation admin router (hot-reload endpoint)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.correlation.admin_router import router as correlation_admin_router
from src.correlation.rule_pack_loader import RulePack, RulePackLoader


def _make_app(engine=None) -> FastAPI:
    app = FastAPI()
    app.include_router(correlation_admin_router)

    # Inject a fake user with manage_settings permission into every request
    @app.middleware("http")
    async def inject_admin(request, call_next):
        request.state.user_sub = "test-admin"
        request.state.user_role = "admin"
        request.state.user_role_id = "role-admin"
        return await call_next(request)

    if engine is not None:
        app.state.correlation_engine = engine

    return app


def _make_mock_engine() -> MagicMock:
    engine = MagicMock()
    engine._rules = {f"rule_{i}": MagicMock() for i in range(9)}
    engine.reload_rules.return_value = 1
    return engine


# Patch require_permission to always pass in these tests
@patch("src.correlation.admin_router.require_permission")
def test_reload_rules_returns_pack_count(mock_perm):
    mock_perm.return_value = None

    engine = _make_mock_engine()
    app = _make_app(engine=engine)
    client = TestClient(app)

    resp = client.post("/api/v1/admin/correlation/reload-rules")
    assert resp.status_code == 200
    data = resp.json()
    assert "reloaded_packs" in data
    assert data["reloaded_packs"] == 1
    assert data["active_rules"] == 9


@patch("src.correlation.admin_router.require_permission")
def test_reload_rules_503_when_engine_dormant(mock_perm):
    mock_perm.return_value = None

    app = _make_app(engine=None)  # no engine on app.state
    client = TestClient(app)

    resp = client.post("/api/v1/admin/correlation/reload-rules")
    assert resp.status_code == 503
    assert "not running" in resp.json()["detail"]


@patch("src.correlation.admin_router.require_permission")
def test_reload_rules_calls_engine_reload_rules(mock_perm):
    mock_perm.return_value = None

    engine = _make_mock_engine()
    app = _make_app(engine=engine)
    client = TestClient(app)

    client.post("/api/v1/admin/correlation/reload-rules")

    engine.reload_rules.assert_called_once()
