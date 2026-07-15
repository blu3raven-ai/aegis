"""Router-level tests for /api/v1/settings/saved-views — auth, validation, response shape.

Service is mocked so these tests stay DB-free. Cross-user isolation lives in
the service-layer tests (test_saved_views_service.py)."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.settings.saved_views.router import router as saved_views_router  # noqa: E402


def _make_app(*, user_sub: str = "user-1") -> FastAPI:
    app = FastAPI()
    app.include_router(saved_views_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = user_sub
        request.state.user_role = "admin"
        return await call_next(request)

    return app


def _make_app_anon() -> FastAPI:
    app = FastAPI()
    app.include_router(saved_views_router)
    return app


def _fake_row(
    *,
    id_: str = "view-1",
    user_id: str = "user-1",
    surface: str = "findings",
    name: str = "KEV-only",
    url_state: dict | None = None,
    is_default: bool = False,
):
    row = MagicMock()
    row.id = id_
    row.user_id = user_id
    row.surface = surface
    row.name = name
    row.url_state = url_state if url_state is not None else {"kev": "true"}
    row.is_default = is_default
    row.created_at = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    row.updated_at = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    return row


@asynccontextmanager
async def _fake_session():
    yield MagicMock()



def test_create_requires_auth():
    client = TestClient(_make_app_anon())
    resp = client.post(
        "/api/v1/settings/saved-views",
        json={"surface": "findings", "name": "X", "url_state": {}},
    )
    assert resp.status_code == 401


def test_patch_requires_auth():
    client = TestClient(_make_app_anon())
    resp = client.patch("/api/v1/settings/saved-views/some-id", json={"name": "Y"})
    assert resp.status_code == 401


def test_delete_requires_auth():
    client = TestClient(_make_app_anon())
    resp = client.delete("/api/v1/settings/saved-views/some-id")
    assert resp.status_code == 401



def test_create_round_trip():
    created = _fake_row(id_="view-new", name="KEV-only")
    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.create_view", new=AsyncMock(return_value=created)) as mock_create:
        client = TestClient(_make_app(user_sub="user-1"))
        resp = client.post(
            "/api/v1/settings/saved-views",
            json={"surface": "findings", "name": "KEV-only", "url_state": {"kev": "true"}},
        )

    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["id"] == "view-new"
    assert body["name"] == "KEV-only"
    # Service receives the authenticated user_id from request.state, not from body.
    kwargs = mock_create.await_args.kwargs
    assert kwargs["user_id"] == "user-1"
    payload = kwargs["payload"]
    assert payload.surface == "findings"
    assert payload.name == "KEV-only"
    assert payload.url_state == {"kev": "true"}


def test_create_missing_field_returns_400():
    client = TestClient(_make_app())
    resp = client.post(
        "/api/v1/settings/saved-views",
        json={"surface": "findings"},  # missing name
    )
    assert resp.status_code == 400
    assert "name" in resp.json()["detail"]


def test_create_defaults_empty_url_state():
    created = _fake_row(url_state={})
    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.create_view", new=AsyncMock(return_value=created)) as mock_create:
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/settings/saved-views",
            json={"surface": "findings", "name": "Empty"},
        )

    assert resp.status_code == 201
    assert mock_create.await_args.kwargs["payload"].url_state == {}


def test_create_service_validation_error_is_400():
    async def _raise(**_kwargs):
        raise ValueError("name must be 1-255 chars")

    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.create_view", side_effect=_raise):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/settings/saved-views",
            json={"surface": "findings", "name": "", "url_state": {}},
        )
    assert resp.status_code == 400



def test_patch_renames_view():
    updated = _fake_row(id_="view-1", name="Renamed")
    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.update_view", new=AsyncMock(return_value=updated)) as mock_update, \
         patch("src.settings.saved_views.router.set_default", new=AsyncMock()) as mock_set_default:
        client = TestClient(_make_app(user_sub="user-1"))
        resp = client.patch("/api/v1/settings/saved-views/view-1", json={"name": "Renamed"})

    assert resp.status_code == 200
    assert resp.json()["name"] == "Renamed"
    mock_set_default.assert_not_awaited()
    kwargs = mock_update.await_args.kwargs
    assert kwargs == {
        "user_id": "user-1",
        "view_id": "view-1",
        "name": "Renamed",
        "url_state": None,
        "session": kwargs["session"],
    }


def test_patch_with_set_default_true_calls_set_default():
    updated = _fake_row(id_="view-1", is_default=True)
    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.update_view", new=AsyncMock()) as mock_update, \
         patch("src.settings.saved_views.router.set_default", new=AsyncMock(return_value=updated)) as mock_set_default:
        client = TestClient(_make_app(user_sub="user-1"))
        resp = client.patch("/api/v1/settings/saved-views/view-1", json={"set_default": True})

    assert resp.status_code == 200
    assert resp.json()["is_default"] is True
    mock_update.assert_not_awaited()
    kwargs = mock_set_default.await_args.kwargs
    assert kwargs["user_id"] == "user-1"
    assert kwargs["view_id"] == "view-1"


def test_patch_not_found_returns_404():
    async def _raise(**_kwargs):
        raise LookupError("saved view not found")

    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.update_view", side_effect=_raise):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/saved-views/nope", json={"name": "X"})
    assert resp.status_code == 404


def test_patch_validation_error_is_400():
    async def _raise(**_kwargs):
        raise ValueError("name must be 1-255 chars")

    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.update_view", side_effect=_raise):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/saved-views/view-1", json={"name": ""})
    assert resp.status_code == 400



def test_delete_returns_204():
    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.delete_view", new=AsyncMock(return_value=None)) as mock_delete:
        client = TestClient(_make_app(user_sub="user-1"))
        resp = client.delete("/api/v1/settings/saved-views/view-1")

    assert resp.status_code == 204
    kwargs = mock_delete.await_args.kwargs
    assert kwargs["user_id"] == "user-1"
    assert kwargs["view_id"] == "view-1"


def test_delete_not_found_returns_404():
    async def _raise(**_kwargs):
        raise LookupError("saved view not found")

    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.delete_view", side_effect=_raise):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/settings/saved-views/nope")
    assert resp.status_code == 404


def test_delete_uses_authenticated_user_not_path_user():
    """Cross-user delete attempts surface as 404 from the service. The router
    must forward the auth identity — not any caller-supplied value — so a
    user B trying to delete user A's view via a guessed id gets 404."""
    async def _raise(**_kwargs):
        raise LookupError("saved view not found")

    with patch("src.settings.saved_views.router.get_session", _fake_session), \
         patch("src.settings.saved_views.router.delete_view", side_effect=_raise) as mock_delete:
        client = TestClient(_make_app(user_sub="user-b"))
        resp = client.delete("/api/v1/settings/saved-views/view-owned-by-a")

    assert resp.status_code == 404
    assert mock_delete.await_args.kwargs["user_id"] == "user-b"
