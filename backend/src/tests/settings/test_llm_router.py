"""Tests for the per-org LLM configuration REST router."""
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

from src.db.helpers import run_db  # noqa: E402
from src.db.models import LlmConfig  # noqa: E402
from src.settings.llm_router import router as llm_router  # noqa: E402

_ADMIN_PERMS = {"manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(llm_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    return app


@pytest.fixture(autouse=True)
def _cleanup_llm_config():
    yield

    async def _q(session: AsyncSession) -> None:
        await session.execute(delete(LlmConfig).where(LlmConfig.org_id == "default"))

    run_db(_q)


def test_get_returns_404_when_unconfigured():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/llm")
        assert resp.status_code == 404
        assert resp.json()["detail"] == "llm_config_not_set"


def test_put_stores_config_and_returns_safe_view():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.put(
            "/api/v1/settings/llm",
            json={
                "api_key": "sk-test-abc",
                "api_base_url": "https://api.example.ai/v1",
                "model": "claude-sonnet-4-6",
                "scan_token_budget": 50_000,
                "daily_token_budget": 500_000,
                "enabled": True,
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert "api_key" not in body
        assert body["configured"] is True
        assert body["api_base_url"] == "https://api.example.ai/v1"
        assert body["model"] == "claude-sonnet-4-6"
        assert body["scan_token_budget"] == 50_000
        assert body["daily_token_budget"] == 500_000
        assert body["enabled"] is True


def test_response_never_leaks_api_key():
    secret = "sk-super-secret-do-not-leak"
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        put_resp = client.put(
            "/api/v1/settings/llm",
            json={
                "api_key": secret,
                "api_base_url": "https://api.example.ai/v1",
                "model": "claude-sonnet-4-6",
            },
        )
        assert put_resp.status_code == 200
        assert secret not in put_resp.text

        get_resp = client.get("/api/v1/settings/llm")
        assert get_resp.status_code == 200
        assert secret not in get_resp.text
        assert "api_key" not in get_resp.json()


def test_non_admin_forbidden():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_NO_PERMS):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/llm")
        assert resp.status_code == 403
