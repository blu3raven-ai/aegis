"""Smoke tests for the findings export REST router — auth + scoping.

Mocks the streaming helpers and DB session so we can verify the router enforces
permissions and threads viewer asset_ids through to the data layer.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.exports.router import router as exports_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_OTHER_ASSET_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_VIEWER_PERMS = {"view_findings"}


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(exports_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


class _NullSession:
    """Minimal async context manager standing in for get_session()."""

    async def __aenter__(self):
        return MagicMock()

    async def __aexit__(self, *args):
        return None


async def _empty_stream(*args, **kwargs):
    # Yield zero chunks — body stays empty so StreamingResponse can complete.
    return
    yield  # noqa: unreachable — keeps this an async generator.


def test_export_findings_threads_viewer_scope():
    """The router must resolve viewer asset_ids and pass them to count/stream."""
    captured: dict = {}

    async def fake_count(filters, asset_ids, session, include_archived_rows=False):
        captured["count_asset_ids"] = asset_ids
        return 0

    async def fake_stream(filters, asset_ids, session, include_archived_rows=False):
        captured["stream_asset_ids"] = asset_ids
        async for chunk in _empty_stream():
            yield chunk

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.exports.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.exports.router.get_session", return_value=_NullSession()), \
         patch("src.exports.router.count_findings", new=fake_count), \
         patch("src.exports.router.stream_findings_csv", new=fake_stream):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/export?format=csv")

    assert resp.status_code == 200
    assert captured["count_asset_ids"] == [_FAKE_ASSET_ID]
    assert captured["stream_asset_ids"] == [_FAKE_ASSET_ID]


def test_export_findings_empty_scope_yields_zero_results():
    """Viewer with no team membership (empty asset_ids) sees zero findings."""
    captured: dict = {}

    async def fake_count(filters, asset_ids, session, include_archived_rows=False):
        captured["asset_ids"] = asset_ids
        return 0

    async def fake_stream(filters, asset_ids, session, include_archived_rows=False):
        async for chunk in _empty_stream():
            yield chunk

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.exports.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[])), \
         patch("src.exports.router.get_session", return_value=_NullSession()), \
         patch("src.exports.router.count_findings", new=fake_count), \
         patch("src.exports.router.stream_findings_csv", new=fake_stream):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/export?format=csv")

    assert resp.status_code == 200
    assert captured["asset_ids"] == []
    assert resp.headers["x-total-count"] == "0"


def test_export_findings_missing_permission_is_403():
    """Caller without view_findings must be denied — no DB calls."""
    called = {"count": False}

    async def fake_count(*args, **kwargs):
        called["count"] = True
        return 0

    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.exports.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.exports.router.get_session", return_value=_NullSession()), \
         patch("src.exports.router.count_findings", new=fake_count):
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.get("/api/v1/findings/export?format=csv")

    assert resp.status_code == 403
    assert called["count"] is False
