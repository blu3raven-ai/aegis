"""Router-layer coverage for the account profile / notification-prefs / avatar endpoints.

These are self-service single-row PATCH/PUT surfaces gated on
require_caller_identity. The fragile bits are the camelCase aliases that cross
the wire — `weeklyDigest` (in and out) and `avatarUrl` (in) — plus the 204s and
the identity gate. Service is mocked so only the router layer is pinned.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from graphql import GraphQLError

from src.auth.account.profile_router import profile_router

_BASE = "/api/v1/settings/account"


def _make_app(*, session=object(), user_sub="user-1") -> FastAPI:
    app = FastAPI()
    app.include_router(profile_router)

    @app.middleware("http")
    async def _inject_state(request, call_next):
        request.state.session = session
        request.state.user_sub = user_sub
        request.state.user_role = "member"
        request.state.user_role_id = None
        request.state.user_org = "acme-org"
        return await call_next(request)

    return app


def _client(**kw) -> TestClient:
    return TestClient(_make_app(**kw))


def _profile():
    return SimpleNamespace(theme="dark", timezone="UTC")


def _prefs(**over):
    base = dict(assignments=True, mentions=False, kev=True, weekly_digest=True, marketing=False)
    base.update(over)
    return SimpleNamespace(**base)


# ── identity gate ────────────────────────────────────────────────────────────

def test_get_profile_403_without_session():
    assert _client(session=None).get(f"{_BASE}/profile").status_code == 403


def test_get_profile_401_without_user():
    assert _client(user_sub=None).get(f"{_BASE}/profile").status_code == 401


# ── profile ──────────────────────────────────────────────────────────────────

def test_get_profile_returns_theme_and_timezone():
    with patch("src.auth.account.profile_router._account_profile", return_value=_profile()):
        resp = _client().get(f"{_BASE}/profile")
    assert resp.status_code == 200
    assert resp.json() == {"theme": "dark", "timezone": "UTC"}


def test_update_profile_forwards_fields():
    with patch("src.auth.account.profile_router._update_account_profile", return_value=_profile()) as svc:
        resp = _client().patch(f"{_BASE}/profile", json={"theme": "light", "timezone": "PST"})
    assert resp.status_code == 200
    assert svc.call_args.kwargs["theme"] == "light"
    assert svc.call_args.kwargs["timezone"] == "PST"


# ── notification prefs (camelCase alias) ─────────────────────────────────────

def test_get_prefs_serializes_weekly_digest_as_camelcase():
    with patch("src.auth.account.profile_router._account_notifications", return_value=_prefs()):
        resp = _client().get(f"{_BASE}/notification-prefs")
    body = resp.json()
    # The wire field is weeklyDigest, never weekly_digest.
    assert body["weeklyDigest"] is True
    assert "weekly_digest" not in body


def test_update_prefs_accepts_camelcase_and_maps_to_service():
    with patch("src.auth.account.profile_router._update_account_notifications", return_value=_prefs(weekly_digest=False)) as svc:
        resp = _client().patch(f"{_BASE}/notification-prefs", json={"weeklyDigest": False, "kev": True})
    assert resp.status_code == 200
    # Inbound weeklyDigest alias resolves to the service's weekly_digest kwarg.
    assert svc.call_args.kwargs["weekly_digest"] is False
    assert svc.call_args.kwargs["kev"] is True
    assert resp.json()["weeklyDigest"] is False


# ── avatar (204 + alias) ─────────────────────────────────────────────────────

def test_set_avatar_accepts_camelcase_and_returns_204():
    with patch("src.auth.account.profile_router._set_avatar") as svc:
        resp = _client().put(f"{_BASE}/avatar", json={"avatarUrl": "https://cdn/a.png"})
    assert resp.status_code == 204
    assert resp.content == b""
    assert svc.call_args.kwargs["avatar_url"] == "https://cdn/a.png"


def test_clear_avatar_returns_204():
    with patch("src.auth.account.profile_router._clear_avatar") as svc:
        resp = _client().delete(f"{_BASE}/avatar")
    assert resp.status_code == 204
    assert svc.called


# ── error translation ────────────────────────────────────────────────────────

def test_update_profile_validation_error_maps_to_400():
    err = GraphQLError("bad timezone", extensions={"code": "VALIDATION_ERROR"})
    with patch("src.auth.account.profile_router._update_account_profile", side_effect=err):
        resp = _client().patch(f"{_BASE}/profile", json={"timezone": "Mars/Olympus"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "bad timezone"
