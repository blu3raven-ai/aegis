"""Tests for GET /api/v1/sources/connections/{connection_id}."""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_SOURCES
from src.sources.source_connections_router import source_connections_router
from src.sources.store import SourceNotFoundError

_VIEW_PERMS = {"view_sources"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_view_sources: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(source_connections_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_sources:
        app.dependency_overrides[Permission(VIEW_SOURCES)] = lambda: None
    return app


def test_get_connection_returns_connection_for_viewer():
    connection = {
        "id": "conn-1",
        "sourceType": "github",
        "category": "code-repositories",
        "name": "Test",
        "status": "connected",
        "auth": {"orgOrOwner": "acme-org"},
        "scanScope": "all-except-excluded",
        "excludedItems": ["acme-org/skip"],
        "syncSchedule": "6h",
        "createdAt": "2026-06-01T00:00:00Z",
        "updatedAt": "2026-06-01T00:00:00Z",
    }
    with patch(
        "src.sources.source_connections_router.sources_store.get_connection",
        return_value=connection,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/conn-1")

    assert resp.status_code == 200
    assert resp.json() == {"connection": connection}


def test_get_connection_returns_404_when_missing():
    with patch(
        "src.sources.source_connections_router.sources_store.get_connection",
        side_effect=SourceNotFoundError("connection 'missing' not found"),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/missing")

    assert resp.status_code == 404


def test_get_connection_rejects_caller_without_view_sources_with_403():
    with (
        patch(
            "src.authz.enforcement.dependencies.has_role_permission",
            return_value=False,
        ),
        patch(
            "src.sources.source_connections_router.sources_store.get_connection",
        ) as mock_get,
    ):
        client = TestClient(_make_app(allow_view_sources=False))
        resp = client.get("/api/v1/sources/connections/conn-1")

    assert resp.status_code == 403
    mock_get.assert_not_called()
