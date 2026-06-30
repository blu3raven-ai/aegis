"""Router-layer coverage for the account TOTP endpoints.

TOTP enrollment/verify/disable act on the caller's own account, so the gate is
require_caller_identity: an interactive session (not a machine/API-key identity)
with a resolved user. These tests mock the service and pin that gate (403 with no
session, 401 with no user), the enroll response shape, the verify wiring, and the
GraphQLError→HTTP translation.
"""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from graphql import GraphQLError

from src.auth.account.totp_router import totp_router

_ENROLL = "/api/v1/auth/totp/enroll"
_VERIFY = "/api/v1/auth/totp/verify"
_DISABLE = "/api/v1/auth/totp/disable"


def _make_app(*, session=object(), user_sub="user-1") -> FastAPI:
    app = FastAPI()
    app.include_router(totp_router)

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


# ── identity gate ────────────────────────────────────────────────────────────

def test_enroll_403_without_interactive_session():
    # Machine identity (no session) must be rejected on a self-service surface.
    resp = _client(session=None).post(_ENROLL)
    assert resp.status_code == 403


def test_enroll_401_without_user():
    resp = _client(user_sub=None).post(_ENROLL)
    assert resp.status_code == 401


def test_disable_403_without_session():
    assert _client(session=None).post(_DISABLE).status_code == 403


# ── enroll ───────────────────────────────────────────────────────────────────

def test_enroll_returns_qr_and_secret():
    result = type("R", (), {"qr_data_url": "data:image/png;base64,AAA", "secret": "JBSWY3DP"})()
    with patch("src.auth.account.totp_router._begin_totp_enrollment", return_value=result):
        resp = _client().post(_ENROLL)
    assert resp.status_code == 200
    body = resp.json()
    assert body["qrDataUrl"] == "data:image/png;base64,AAA"
    assert body["secret"] == "JBSWY3DP"


# ── verify ───────────────────────────────────────────────────────────────────

def test_verify_forwards_code_and_returns_ok():
    with patch("src.auth.account.totp_router._verify_totp_enrollment") as svc:
        resp = _client().post(_VERIFY, json={"code": "123456"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert svc.call_args.kwargs["code"] == "123456"


def test_verify_invalid_code_maps_to_400():
    err = GraphQLError("invalid code", extensions={"code": "VALIDATION_ERROR"})
    with patch("src.auth.account.totp_router._verify_totp_enrollment", side_effect=err):
        resp = _client().post(_VERIFY, json={"code": "000000"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid code"


# ── disable ──────────────────────────────────────────────────────────────────

def test_disable_returns_ok():
    with patch("src.auth.account.totp_router._disable_totp") as svc:
        resp = _client().post(_DISABLE)
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert svc.called
