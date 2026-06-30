"""Tests for the per-org Argus connection REST router."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import ArgusConnection  # noqa: E402
from src.settings.argus.router import router as argus_router  # noqa: E402

_ADMIN_PERMS = {"manage_settings"}


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(argus_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


@pytest.fixture(autouse=True)
def _cleanup_argus_connection():
    yield

    async def _q(session: AsyncSession) -> None:
        await session.execute(delete(ArgusConnection).where(ArgusConnection.org_id == "default"))

    run_db(_q)


def test_get_returns_empty_status_when_unconfigured():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/argus")
        assert resp.status_code == 200
        assert resp.json() == {
            "endpoint": "", "token_endpoint": "", "client_id": "", "enabled": False, "connected": False,
        }


def test_put_stores_connection_and_returns_safe_view():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.put(
            "/api/v1/settings/argus",
            json={
                "endpoint": "https://argus.example.ai",
                "token_endpoint": "https://argus.example.ai/oauth/token",
                "client_id": "aegis-client",
                "refresh_token": "argus-refresh-abc",
                "enabled": True,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "refresh_token" not in body
        assert body["endpoint"] == "https://argus.example.ai"
        assert body["client_id"] == "aegis-client"
        assert body["enabled"] is True
        assert body["connected"] is True


def test_response_never_leaks_token():
    secret = "argus-super-secret-do-not-leak"
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        put_resp = client.put(
            "/api/v1/settings/argus",
            json={
                "endpoint": "https://argus.example.ai",
                "token_endpoint": "https://argus.example.ai/oauth/token",
                "client_id": "aegis-client",
                "refresh_token": secret,
                "enabled": True,
            },
        )
        assert put_resp.status_code == 200
        assert secret not in put_resp.text

        get_resp = client.get("/api/v1/settings/argus")
        assert get_resp.status_code == 200
        assert secret not in get_resp.text
        assert "refresh_token" not in get_resp.json()


def test_delete_removes_connection():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        client.put(
            "/api/v1/settings/argus",
            json={
                "endpoint": "https://argus.example.ai",
                "token_endpoint": "https://argus.example.ai/oauth/token",
                "client_id": "c", "refresh_token": "rt", "enabled": True,
            },
        )
        del_resp = client.delete("/api/v1/settings/argus")
        assert del_resp.status_code == 200
        assert del_resp.json() == {"deleted": True}

        # Second delete -> 404.
        assert client.delete("/api/v1/settings/argus").status_code == 404


def test_test_endpoint_reports_auth_failure(monkeypatch):
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        client.put(
            "/api/v1/settings/argus",
            json={
                "endpoint": "https://argus.example.ai",
                "token_endpoint": "https://argus.example.ai/oauth/token",
                "client_id": "c", "refresh_token": "rt", "enabled": True,
            },
        )
        from src.settings.argus import router as argus_router
        from src.settings.argus.service import ArgusAuthError

        def _boom(_conn):
            raise ArgusAuthError("invalid_grant")

        monkeypatch.setattr(argus_router, "mint_argus_access_token", _boom)
        resp = client.post("/api/v1/settings/argus/test")
        assert resp.status_code == 200
        assert resp.json()["ok"] is False
        assert resp.json()["error"] == "auth_failed"


def test_non_admin_forbidden():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_settings=False))
        resp = client.get("/api/v1/settings/argus")
        assert resp.status_code == 403
