"""Tests for GET /api/v1/sources/connections/counts."""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_SOURCES
from src.sources.source_connections_router import source_connections_router

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


def test_get_counts_returns_rows_for_viewer():
    with patch(
        "src.sources.source_connections_router.sources_store.count_by_category",
        return_value={"code-repositories": 3, "container-registry": 1},
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/counts")

    assert resp.status_code == 200
    rows = {row["category"]: row["count"] for row in resp.json()["counts"]}
    assert rows == {"code-repositories": 3, "container-registry": 1}


def test_get_counts_rejects_caller_without_view_sources_with_403():
    with (
        patch(
            "src.authz.enforcement.dependencies.has_role_permission",
            return_value=False,
        ),
        patch(
            "src.sources.source_connections_router.sources_store.count_by_category",
        ) as mock_count,
    ):
        client = TestClient(_make_app(allow_view_sources=False))
        resp = client.get("/api/v1/sources/connections/counts")

    assert resp.status_code == 403
    mock_count.assert_not_called()
