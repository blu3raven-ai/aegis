"""Tests for the LLM daily-usage REST router."""
from __future__ import annotations

import datetime as dt
import os
from unittest.mock import patch

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
from src.db.models import LlmConfig, LlmUsageDaily  # noqa: E402
from src.settings.llm.service import LlmConfigUpsert, upsert_llm_config  # noqa: E402
from src.settings.llm.usage import record_usage  # noqa: E402
from src.settings.llm.usage_router import router as llm_usage_router  # noqa: E402

_ADMIN_PERMS = {"manage_settings"}


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(llm_usage_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = "admin"
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    async def _q(session: AsyncSession) -> None:
        await session.execute(
            delete(LlmUsageDaily).where(LlmUsageDaily.org_id == "default")
        )
        await session.execute(delete(LlmConfig).where(LlmConfig.org_id == "default"))
    run_db(_q)


def test_usage_with_no_history_returns_zeroed_series():
    with patch(
        "src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/llm/usage?days=7")

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["days"]) == 7
    assert all(d["tokens_in"] == 0 and d["tokens_out"] == 0 for d in body["days"])
    assert body["today_used"] == 0
    assert body["today_budget"] == 0


def test_usage_returns_recorded_history():
    upsert_llm_config(
        LlmConfigUpsert(
            org_id="default",
            api_key="sk-test",
            api_base_url="https://x/v1",
            model="m",
            daily_token_budget=10_000,
        )
    )
    record_usage(org_id="default", tokens_in=400, tokens_out=100, scans=1)

    with patch(
        "src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/llm/usage?days=7")

    body = resp.json()
    assert body["today_used"] == 500
    assert body["today_budget"] == 10_000
    assert body["today_remaining"] == 9_500
    today_iso = dt.datetime.now(dt.timezone.utc).date().isoformat()
    today_row = next(d for d in body["days"] if d["date"] == today_iso)
    assert today_row["tokens_in"] == 400
    assert today_row["tokens_out"] == 100


def test_usage_rejects_out_of_range_days():
    with patch(
        "src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/settings/llm/usage?days=400")
    assert resp.status_code == 422
