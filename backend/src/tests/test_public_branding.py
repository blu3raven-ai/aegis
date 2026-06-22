"""Tests for the public GET /api/v1/settings/organisations/branding endpoint.

No session cookie, no CSRF token — this endpoint is explicitly listed in
session_gate.PUBLIC_PATHS so unauthenticated access is expected.
"""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.settings.organisations.router import router  # noqa: E402
from src.main import app as main_app  # noqa: E402


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_branding_returns_200_with_no_row(client: TestClient):
    with patch("src.settings.organisations.router.run_db", return_value={"name": None, "logoDataUrl": None, "updatedAt": None}):
        resp = client.get("/api/v1/settings/organisations/branding")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] is None
    assert body["logoDataUrl"] is None
    assert "updatedAt" in body
    assert body["updatedAt"] is None


def test_branding_returns_name_and_logo(client: TestClient):
    payload = {"name": "Acme Corp", "logoDataUrl": "data:image/png;base64,aGVsbG8=", "updatedAt": "2026-06-01T00:00:00+00:00"}
    with patch("src.settings.organisations.router.run_db", return_value=payload):
        resp = client.get("/api/v1/settings/organisations/branding")
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == "Acme Corp"
    assert body["logoDataUrl"] == "data:image/png;base64,aGVsbG8="
    assert body["updatedAt"] == "2026-06-01T00:00:00+00:00"


def test_branding_requires_no_cookie(client: TestClient):
    """Verify no Set-Cookie header is emitted and the request needs no credentials."""
    with patch("src.settings.organisations.router.run_db", return_value={"name": None, "logoDataUrl": None}):
        resp = client.get("/api/v1/settings/organisations/branding")
    assert resp.status_code == 200
    assert "set-cookie" not in resp.headers


def test_branding_response_shape_is_camel_case(client: TestClient):
    """Wire format uses camelCase keys (logoDataUrl not logo_data_url)."""
    with patch("src.settings.organisations.router.run_db", return_value={"name": "X", "logoDataUrl": "data:image/png;base64,AA==", "updatedAt": None}):
        resp = client.get("/api/v1/settings/organisations/branding")
    body = resp.json()
    assert "logoDataUrl" in body
    assert "logo_data_url" not in body
    assert "updatedAt" in body


# ---------------------------------------------------------------------------
# Integration test: exercises the real main.app stack (require_jwt included)
# This test fails if the branding path is absent from require_jwt's open_paths.
# ---------------------------------------------------------------------------

def test_branding_accessible_without_auth_via_main_app():
    """GET /api/v1/settings/organisations/branding must return 200 with no auth header.

    This test uses the production ``main.app`` so the real ``require_jwt``
    middleware is in play. It would have returned 401 before the path was
    added to ``open_paths``.

    The lifespan (Alembic, MinIO, scheduler) is suppressed — we only need
    the middleware stack to be wired up; no running services are required.
    """
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock

    branding_payload = {"name": None, "logoDataUrl": None, "updatedAt": None}

    @asynccontextmanager
    async def _noop_lifespan(app):
        yield

    with patch("src.main.lifespan", _noop_lifespan), \
         patch("src.settings.organisations.router.run_db", return_value=branding_payload):
        # TestClient without the context-manager protocol skips lifespan
        real_client = TestClient(main_app, raise_server_exceptions=True)
        resp = real_client.get(
            "/api/v1/settings/organisations/branding",
            # No Authorization header, no session cookie
        )
    assert resp.status_code == 200, (
        f"Expected 200 without auth; got {resp.status_code}. "
        "Ensure '/api/v1/settings/organisations/branding' is in require_jwt's open_paths."
    )
    body = resp.json()
    assert "updatedAt" in body
