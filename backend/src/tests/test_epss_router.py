"""Permission and asset-scope tests for /api/v1/sla/epss.

The /top endpoint scopes by the caller's accessible asset_ids; the legacy
``?org_id=`` query-param fallback was a BOLA vector and has been removed.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.epss.router import router as epss_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(epss_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def test_top_requires_view_findings():
    """Caller without view_findings gets 403 before any scope lookup runs."""
    called = {"scope": False}

    async def fake_scope(*args, **kwargs):
        called["scope"] = True
        return [_FAKE_ASSET_ID]

    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.epss.router.resolve_asset_ids_from_request", side_effect=fake_scope):
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.get("/api/v1/sla/epss/top")
        assert resp.status_code == 403
        assert called["scope"] is False


def test_top_uses_caller_scoped_asset_ids():
    """The service is invoked with the caller's resolved asset_ids — not any
    client-supplied org_id (the query-param fallback has been removed)."""
    captured: dict = {}

    def _fake_top(asset_ids, limit):
        captured["asset_ids"] = asset_ids
        captured["limit"] = limit
        return []

    with patch("src.epss.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.epss.router._service.top_findings_by_epss", side_effect=_fake_top):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sla/epss/top")
        assert resp.status_code == 200
        assert captured["asset_ids"] == [_FAKE_ASSET_ID]
        assert captured["limit"] == 20


def test_top_ignores_legacy_org_id_query_param():
    """The legacy ?org_id= query string used to widen scope; today it is
    silently ignored and the response is scoped to the caller's grants."""
    captured: dict = {}

    def _fake_top(asset_ids, limit):
        captured["asset_ids"] = asset_ids
        return []

    with patch("src.epss.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.epss.router._service.top_findings_by_epss", side_effect=_fake_top):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sla/epss/top?org_id=evil-org")
        assert resp.status_code == 200
        assert captured["asset_ids"] == [_FAKE_ASSET_ID]


def test_top_empty_scope_returns_empty_list():
    """Caller with no asset access gets a clean empty response — the service
    isn't even invoked (avoids running the SQL query for a known-empty
    result)."""
    with patch("src.epss.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[])), \
         patch("src.epss.router._service.top_findings_by_epss") as mock_top:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sla/epss/top")
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"findings": [], "count": 0}
        mock_top.assert_not_called()
