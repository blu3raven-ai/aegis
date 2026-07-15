"""Regression tests for the GET /api/v1/auth/me wire shape."""
from __future__ import annotations

from types import SimpleNamespace

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.auth.authentication.login_router import login_router


def _make_app(*, user=None) -> FastAPI:
    """Build a minimal app that injects request.state.user via middleware."""
    app = FastAPI()
    app.include_router(login_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user = user
        return await call_next(request)

    return app


def _fake_user(*, totp_enabled: bool) -> SimpleNamespace:
    """Stand-in for the User row that the SessionAuthMiddleware would attach.

    Only the attributes the /me handler reads need to be present.
    """
    return SimpleNamespace(
        id="user-abc",
        username="alice",
        email="alice@example.com",
        role="admin",
        role_id="role_admin",
        status="active",
        session_version=2,
        totp_enabled=totp_enabled,
        avatar_url="https://example.com/avatar.png",
    )


def test_me_returns_totp_enabled_true():
    """When the user has TOTP enabled the wire field must be `totpEnabled`.

    Lock the camelCase name — the FE reads `user.totpEnabled` on the Account
    settings page, and a rename to anything else (a previous regression used
    `mfaEnabled`) silently breaks the TOTP-enrolled state display.
    """
    client = TestClient(_make_app(user=_fake_user(totp_enabled=True)))
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["totpEnabled"] is True
    assert "mfaEnabled" not in body["user"]


def test_me_returns_totp_enabled_false():
    client = TestClient(_make_app(user=_fake_user(totp_enabled=False)))
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    assert resp.json()["user"]["totpEnabled"] is False


def test_me_401_when_no_session_user():
    client = TestClient(_make_app(user=None))
    resp = client.get("/api/v1/auth/me")
    assert resp.status_code == 401
