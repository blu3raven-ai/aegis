"""Tests for GET /api/v1/settings/tools/{tool}/prerequisites."""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.settings.general.router import router as settings_router

_MANAGE_PERMS = {"manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(settings_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def test_prerequisites_requires_manage_settings():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_manage_settings=False))
        resp = client.get("/api/v1/settings/tools/dependencies_scanning/prerequisites")
        assert resp.status_code == 403


def test_prerequisites_rejects_unknown_tool():
    with patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_MANAGE_PERMS,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/tools/not_a_real_scanner/prerequisites")
        assert resp.status_code == 422


def test_prerequisites_returns_no_runner_when_no_runner_online():
    with patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_MANAGE_PERMS,
    ), patch(
        "src.runner.registry.list_approved_online_runners",
        return_value=[],
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/tools/dependencies_scanning/prerequisites")
        assert resp.status_code == 200
        body = resp.json()
        assert body["runner_connected"] is False
        assert body["scanner_status"] == "no_runner"
        assert body["error"] == "No runner connected"


def test_prerequisites_returns_ready_when_runner_heartbeat_is_fresh():
    from datetime import datetime, timezone

    fresh = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    with patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_MANAGE_PERMS,
    ), patch(
        "src.runner.registry.list_approved_online_runners",
        return_value=[{"name": "runner-1", "lastSeen": fresh}],
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/tools/code_scanning/prerequisites")
        assert resp.status_code == 200
        body = resp.json()
        assert body["runner_connected"] is True
        assert body["scanner_status"] == "ready"
        assert body["runner_name"] == "runner-1"


def test_prerequisites_accepts_all_five_valid_tools():
    """Lock the canonical slug list so the FE PrerequisitePanel hooks stay in sync."""
    with patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_MANAGE_PERMS,
    ), patch(
        "src.runner.registry.list_approved_online_runners",
        return_value=[],
    ):
        client = TestClient(_make_app())
        for tool in (
            "dependencies_scanning",
            "code_scanning",
            "container_scanning",
            "secret_scanning",
            "iac_scanning",
        ):
            resp = client.get(f"/api/v1/settings/tools/{tool}/prerequisites")
            assert resp.status_code == 200, f"{tool}: {resp.status_code} {resp.text}"
