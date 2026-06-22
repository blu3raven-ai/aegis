"""Tests for the organisation settings REST mutation endpoints.

PATCH  /api/v1/settings/organisations      — update org name
PUT    /api/v1/settings/organisations/logo — set logo
DELETE /api/v1/settings/organisations/logo — clear logo

Auth (MANAGE_ORGANISATIONS) and CSRF are tested against both the isolated
router fixture and the real main.app stack.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_ORGANISATIONS  # noqa: E402
from src.settings.organisations.router import router  # noqa: E402
from src.main import app as main_app  # noqa: E402

_MANAGE_ORGS = {"manage_organisations"}
_NO_PERMS: set[str] = set()

_VALID_PNG = "data:image/png;base64,aGVsbG8="
_VALID_JPEG = "data:image/jpeg;base64,aGVsbG8="
_VALID_WEBP = "data:image/webp;base64,aGVsbG8="

_BRANDING_PAYLOAD = {"name": "Acme Corp", "logoDataUrl": _VALID_PNG, "updatedAt": "2026-06-01T00:00:00+00:00"}
_NO_LOGO_PAYLOAD = {"name": "Acme Corp", "logoDataUrl": None, "updatedAt": "2026-06-01T00:00:00+00:00"}


def _make_app(*, allow_manage_orgs: bool = True) -> FastAPI:
    """Isolated router fixture — no JWT/CSRF middleware."""
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_orgs:
        app.dependency_overrides[Permission(MANAGE_ORGANISATIONS)] = lambda: None
    return app


# ---------------------------------------------------------------------------
# PATCH /api/v1/settings/organisations — update name
# ---------------------------------------------------------------------------

def test_patch_requires_manage_orgs():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_orgs=False))
        resp = client.patch("/api/v1/settings/organisations", json={"name": "New Name"})
    assert resp.status_code == 403


def test_patch_updates_name_and_returns_branding():
    payload = {"name": "New Name", "logoDataUrl": None, "updatedAt": "2026-06-17T00:00:00+00:00"}
    with (
        patch("src.settings.organisations.router.run_db", return_value=payload),
    ):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/organisations", json={"name": "New Name"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "New Name"
    assert "logoDataUrl" in body
    assert "updatedAt" in body


def test_patch_with_null_name_accepted():
    payload = {"name": None, "logoDataUrl": None, "updatedAt": "2026-06-17T00:00:00+00:00"}
    with (
        patch("src.settings.organisations.router.run_db", return_value=payload),
    ):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/organisations", json={"name": None})
    assert resp.status_code == 200
    assert resp.json()["name"] is None


def test_patch_with_whitespace_only_name_stored_as_null():
    """Whitespace-only name must be treated as absent (None), not stored as empty string."""
    payload = {"name": None, "logoDataUrl": None, "updatedAt": "2026-06-17T00:00:00+00:00"}
    with (
        patch("src.settings.organisations.router.run_db", return_value=payload),
    ):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/organisations", json={"name": "   "})
    assert resp.status_code == 200
    assert resp.json()["name"] is None


# ---------------------------------------------------------------------------
# PUT /api/v1/settings/organisations/logo — set logo
# ---------------------------------------------------------------------------

def test_put_logo_requires_manage_orgs():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_orgs=False))
        resp = client.put("/api/v1/settings/organisations/logo", json={"dataUrl": _VALID_PNG})
    assert resp.status_code == 403


def test_put_logo_rejects_oversized_data_url():
    huge = "data:image/png;base64," + ("A" * (200 * 1024 + 1))
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_ORGS):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/settings/organisations/logo", json={"dataUrl": huge})
    assert resp.status_code == 400


def test_put_logo_rejects_wrong_mime():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_ORGS):
        client = TestClient(_make_app())
        resp = client.put(
            "/api/v1/settings/organisations/logo",
            json={"dataUrl": "data:image/tiff;base64,abc"},
        )
    assert resp.status_code == 400


def test_put_logo_rejects_svg():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE_ORGS):
        client = TestClient(_make_app())
        resp = client.put(
            "/api/v1/settings/organisations/logo",
            json={"dataUrl": "data:image/svg+xml;base64,PHN2Zy8+"},
        )
    assert resp.status_code == 400


def test_put_logo_accepts_valid_png():
    with (
        patch("src.settings.organisations.router.run_db", return_value=_BRANDING_PAYLOAD),
    ):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/settings/organisations/logo", json={"dataUrl": _VALID_PNG})
    assert resp.status_code == 200
    assert resp.json()["logoDataUrl"] == _VALID_PNG


def test_put_logo_accepts_valid_jpeg():
    payload = {**_BRANDING_PAYLOAD, "logoDataUrl": _VALID_JPEG}
    with (
        patch("src.settings.organisations.router.run_db", return_value=payload),
    ):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/settings/organisations/logo", json={"dataUrl": _VALID_JPEG})
    assert resp.status_code == 200


def test_put_logo_accepts_valid_webp():
    payload = {**_BRANDING_PAYLOAD, "logoDataUrl": _VALID_WEBP}
    with (
        patch("src.settings.organisations.router.run_db", return_value=payload),
    ):
        client = TestClient(_make_app())
        resp = client.put("/api/v1/settings/organisations/logo", json={"dataUrl": _VALID_WEBP})
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# DELETE /api/v1/settings/organisations/logo — clear logo
# ---------------------------------------------------------------------------

def test_delete_logo_requires_manage_orgs():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_orgs=False))
        resp = client.delete("/api/v1/settings/organisations/logo")
    assert resp.status_code == 403


def test_delete_logo_clears_logo_and_returns_branding():
    with (
        patch("src.settings.organisations.router.run_db", return_value=_NO_LOGO_PAYLOAD),
    ):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/settings/organisations/logo")
    assert resp.status_code == 200
    body = resp.json()
    assert body["logoDataUrl"] is None
    assert "name" in body
    assert "updatedAt" in body


# ---------------------------------------------------------------------------
# CSRF — verified against the real main.app stack
# ---------------------------------------------------------------------------

def _make_noop_lifespan():
    @asynccontextmanager
    async def _noop(app):
        yield
    return _noop


def test_patch_requires_csrf_on_main_app():
    """PATCH without CSRF token must be rejected by the middleware."""
    with (
        patch("src.main.lifespan", _make_noop_lifespan()),
    ):
        client = TestClient(main_app, raise_server_exceptions=False)
        resp = client.patch(
            "/api/v1/settings/organisations",
            json={"name": "No CSRF"},
            cookies={"session": "fake-session"},
        )
    # CSRF middleware rejects the request before it reaches the handler
    assert resp.status_code in (401, 403)


def test_put_logo_requires_csrf_on_main_app():
    """PUT /logo without CSRF token must be rejected by the middleware."""
    with (
        patch("src.main.lifespan", _make_noop_lifespan()),
    ):
        client = TestClient(main_app, raise_server_exceptions=False)
        resp = client.put(
            "/api/v1/settings/organisations/logo",
            json={"dataUrl": _VALID_PNG},
            cookies={"session": "fake-session"},
        )
    assert resp.status_code in (401, 403)


def test_delete_logo_requires_csrf_on_main_app():
    """DELETE /logo without CSRF token must be rejected by the middleware."""
    with (
        patch("src.main.lifespan", _make_noop_lifespan()),
    ):
        client = TestClient(main_app, raise_server_exceptions=False)
        resp = client.delete(
            "/api/v1/settings/organisations/logo",
            cookies={"session": "fake-session"},
        )
    assert resp.status_code in (401, 403)
