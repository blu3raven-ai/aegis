"""Tests for per-org BYO LLM credential storage and retrieval."""
from __future__ import annotations

import os
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import LlmConfig  # noqa: E402
from src.settings.llm.router import router as llm_router  # noqa: E402
from src.settings.llm.service import (  # noqa: E402
    LLM_CONFIG_KEY,
    LlmConfigUpsert,
    build_llm_scan_env,
    fetch_llm_config,
    fetch_public_llm_config,
    upsert_llm_config,
)

_ADMIN_PERMS = {"manage_settings"}


@pytest.fixture(autouse=True)
def _allow_llm_base_url():
    """These tests exercise storage/response shape, not the SSRF guard, so
    neutralize the base-URL validation for their placeholder URLs."""
    with patch("src.settings.llm.service.assert_sendable_url", lambda *_a, **_k: None):
        yield


@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid4()}"


def test_upsert_stores_encrypted_key(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-test-abc",
        api_base_url="https://api.example.ai/v1",
        model="claude-sonnet-4-6",
    ))
    cfg = fetch_llm_config(org_id)
    assert cfg is not None
    assert cfg.api_key == "sk-test-abc"
    assert cfg.api_base_url == "https://api.example.ai/v1"
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.enabled is False


def test_fetch_returns_none_for_unknown_org(db_session):
    assert fetch_llm_config(f"never-existed-{uuid4()}") is None


def test_public_view_omits_api_key(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-secret",
        api_base_url="https://x",
        model="m",
    ))
    pub = fetch_public_llm_config(org_id)
    assert pub is not None
    assert "api_key" not in pub
    assert pub["configured"] is True


def test_transport_defaults_to_auto(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-test",
        api_base_url="https://x",
        model="m",
    ))
    cfg = fetch_llm_config(org_id)
    assert cfg is not None
    assert cfg.transport == "auto"
    assert cfg.anthropic_base_url == ""
    pub = fetch_public_llm_config(org_id)
    assert pub is not None
    assert pub["transport"] == "auto"
    assert pub["anthropic_base_url"] == ""


def test_transport_round_trips_through_upsert_fetch(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-test",
        api_base_url="https://x",
        model="m",
        transport="anthropic",
        anthropic_base_url="https://api.example.ai",
    ))
    cfg = fetch_llm_config(org_id)
    assert cfg is not None
    assert cfg.transport == "anthropic"
    assert cfg.anthropic_base_url == "https://api.example.ai"


@pytest.fixture
def _cleanup_default():
    yield
    async def _q(session: AsyncSession) -> None:
        await session.execute(
            delete(LlmConfig).where(LlmConfig.org_id == LLM_CONFIG_KEY)
        )
    run_db(_q)


def test_job_env_injects_transport_and_optional_anthropic_base(
    db_session, _cleanup_default
):
    upsert_llm_config(LlmConfigUpsert(
        org_id=LLM_CONFIG_KEY,
        api_key="sk-test",
        api_base_url="https://x",
        model="m",
        enabled=True,
        transport="anthropic",
        anthropic_base_url="https://api.example.ai",
    ))
    env = build_llm_scan_env()
    assert env["LLM_TRANSPORT"] == "anthropic"
    assert env["LLM_ANTHROPIC_BASE_URL"] == "https://api.example.ai"


def test_job_env_omits_anthropic_base_when_unset(db_session, _cleanup_default):
    upsert_llm_config(LlmConfigUpsert(
        org_id=LLM_CONFIG_KEY,
        api_key="sk-test",
        api_base_url="https://x",
        model="m",
        enabled=True,
    ))
    env = build_llm_scan_env()
    assert env["LLM_TRANSPORT"] == "auto"
    assert "LLM_ANTHROPIC_BASE_URL" not in env


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(llm_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = "admin"
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def test_put_rejects_invalid_transport(db_session):
    with patch(
        "src.authz.enforcement._resolve_effective_permissions",
        return_value=_ADMIN_PERMS,
    ):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/settings/llm", json={
            "api_key": "sk-test",
            "api_base_url": "https://x/v1",
            "model": "m",
            "transport": "bogus",
        })
    assert resp.status_code == 422
