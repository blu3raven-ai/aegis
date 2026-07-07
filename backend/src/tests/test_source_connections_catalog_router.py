"""Tests for the catalog-style source-connection list reads.

GET /api/v1/sources/connections          — requires VIEW_SOURCES
GET /api/v1/sources/connections/internal-orgs — requires VIEW_SOURCES

Also validates route-order: /counts and /{id} must still resolve without
being shadowed by the new bare /connections or /internal-orgs registrations.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_SOURCES  # noqa: E402
from src.sources.source_connections_router import source_connections_router  # noqa: E402
from src.main import app as main_app  # noqa: E402

_VIEW_PERMS = {"view_sources"}
_NO_PERMS: set[str] = set()

_CANNED_CONNECTION = {
    "id": "conn-1",
    "sourceType": "github",
    "category": "code-repositories",
    "name": "Test Repo",
    "status": "connected",
    "auth": {"orgOrOwner": "example-org"},
    "scanScope": "all",
    "excludedItems": [],
    "syncSchedule": "6h",
    "statusMessage": None,
    "lastSyncedAt": None,
    "nextSyncAt": None,
    "discoveredItemCount": None,
    "discoveredItems": [],
    "createdAt": "2026-06-01T00:00:00Z",
    "updatedAt": "2026-06-01T00:00:00Z",
}


def _make_app(*, allow_view_sources: bool = True) -> FastAPI:
    """Isolated router — no JWT/session/CSRF middleware."""
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


# ---------------------------------------------------------------------------
# GET /connections
# ---------------------------------------------------------------------------

def test_get_connections_returns_list_for_viewer():
    with patch(
        "src.sources.source_connections_router.sources_store.list_connections",
        return_value=[_CANNED_CONNECTION],
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections")

    assert resp.status_code == 200
    body = resp.json()
    assert "connections" in body
    assert len(body["connections"]) == 1
    conn = body["connections"][0]
    assert conn["id"] == "conn-1"
    assert conn["sourceType"] == "github"
    assert conn["category"] == "code-repositories"
    assert conn["auth"]["orgOrOwner"] == "example-org"
    assert conn["scanScope"] == "all"
    assert conn["excludedItems"] == []


def test_get_connections_rejects_without_view_sources():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_view_sources=False))
        resp = client.get("/api/v1/sources/connections")

    assert resp.status_code == 403


def test_get_connections_passes_category_filter():
    list_mock = MagicMock(return_value=[])
    with patch(
        "src.sources.source_connections_router.sources_store.list_connections",
        list_mock,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections?category=code-repositories")

    assert resp.status_code == 200
    list_mock.assert_called_once_with(category="code-repositories", org_id="default")


def test_get_connections_no_category_passes_none():
    list_mock = MagicMock(return_value=[])
    with patch(
        "src.sources.source_connections_router.sources_store.list_connections",
        list_mock,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections")

    assert resp.status_code == 200
    list_mock.assert_called_once_with(category=None, org_id="default")


# ---------------------------------------------------------------------------
# GET /connections/internal-orgs
# ---------------------------------------------------------------------------

def test_get_internal_orgs_returns_minimal_shape():
    with (
        patch(
            "src.sources.source_connections_router.sources_store.list_connections",
            return_value=[_CANNED_CONNECTION],
        ),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/internal-orgs")

    assert resp.status_code == 200
    body = resp.json()
    assert "connections" in body
    assert len(body["connections"]) == 1
    entry = body["connections"][0]
    assert entry["orgOrOwner"] == "example-org"
    assert entry["sourceType"] == "github"
    assert entry["category"] == "code-repositories"
    assert entry["status"] == "connected"
    # Verify tokens/secrets from auth dict are not surfaced
    assert "token" not in entry
    assert "auth" not in entry


def test_get_internal_orgs_rejects_without_view_sources():
    """internal-orgs discloses the connected org/owner inventory → view_sources-gated."""
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_view_sources=False))
        resp = client.get("/api/v1/sources/connections/internal-orgs")

    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Session gate — tested against the real main.app stack
# ---------------------------------------------------------------------------

def _make_noop_lifespan():
    @asynccontextmanager
    async def _noop(app):
        yield
    return _noop


def test_get_connections_requires_session_on_main_app():
    """GET /connections without a session cookie must be rejected with 401."""
    with patch("src.main.lifespan", _make_noop_lifespan()):
        client = TestClient(main_app, raise_server_exceptions=False)
        resp = client.get("/api/v1/sources/connections")
    assert resp.status_code == 401


def test_get_internal_orgs_requires_session_on_main_app():
    """GET /connections/internal-orgs without a session cookie must be rejected with 401."""
    with patch("src.main.lifespan", _make_noop_lifespan()):
        client = TestClient(main_app, raise_server_exceptions=False)
        resp = client.get("/api/v1/sources/connections/internal-orgs")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Route-order regression: existing routes must still resolve correctly
# ---------------------------------------------------------------------------

def test_get_counts_still_resolves_after_new_routes():
    """The new bare /connections must not shadow /connections/counts."""
    with patch(
        "src.sources.source_connections_router.sources_store.count_by_category",
        return_value={"code-repositories": 2},
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/counts")

    assert resp.status_code == 200
    body = resp.json()
    rows = {row["category"]: row["count"] for row in body["counts"]}
    assert rows == {"code-repositories": 2}


def test_get_connection_by_id_still_resolves_after_new_routes():
    """The new literal routes must not shadow /connections/{connection_id}."""
    with patch(
        "src.sources.source_connections_router.sources_store.get_connection",
        return_value=_CANNED_CONNECTION,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sources/connections/conn-1")

    assert resp.status_code == 200
    assert resp.json() == {"connection": _CANNED_CONNECTION}
