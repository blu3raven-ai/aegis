"""Router-layer coverage for the OIDC SSO login + callback routes.

The security-critical contract is the callback's CSRF defence: the state cookie
must be present and its decoded `state` must equal the query `state`, and every
failure path must land on a generic /login error rather than leaking detail or
proceeding. Login must gate on SSO being enabled and bind the state cookie.
External IO (config load, IdP calls, session issue) is mocked.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.auth.federation.oidc_router import _redirect_uri, oidc_router

_MOD = "src.auth.federation.oidc_router"
_LOGIN = "/auth/sso/oidc/login"
_CB = "/auth/sso/oidc/callback"
_COOKIE = "__Host-sso-oidc-state"

_CFG = SimpleNamespace(enabled=True, protocol="oidc")


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(oidc_router)
    return TestClient(app)


def _run_db(*, cfg=_CFG, do_ok=True):
    """Stand-in for run_db that dispatches on the wrapped coroutine's name."""
    def _fake(coro_fn):
        if coro_fn.__name__ == "_load_config":
            return cfg
        return do_ok  # the inner _do closure

    return _fake


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_redirect_uri_built_from_request_origin():
    # The redirect_uri must match what was registered at the IdP, derived from
    # the request's scheme+host.
    with patch(_MOD + ".run_db", _run_db(cfg=None)):
        resp = _client().get(_LOGIN, follow_redirects=False, headers={"host": "aegis.example"})
    # cfg=None short-circuits, but the helper itself is exercised below directly.
    req = SimpleNamespace(url=SimpleNamespace(scheme="https", netloc="aegis.example"), headers={"host": "aegis.example"})
    assert _redirect_uri(req) == "https://aegis.example/auth/sso/oidc/callback"


# ── login ────────────────────────────────────────────────────────────────────

def test_login_redirects_to_error_when_sso_disabled():
    with patch(_MOD + ".run_db", _run_db(cfg=None)):
        resp = _client().get(_LOGIN, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?error=sso_disabled"


def test_login_redirects_to_idp_and_sets_state_cookie():
    with patch(_MOD + ".run_db", _run_db()), \
            patch(_MOD + ".authorize_url", AsyncMock(return_value="https://idp/authorize?x=1")), \
            patch(_MOD + ".encode_state", return_value="ENCSTATE"):
        resp = _client().get(_LOGIN, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "https://idp/authorize?x=1"
    set_cookie = resp.headers.get("set-cookie", "")
    assert _COOKIE in set_cookie
    assert "httponly" in set_cookie.lower()
    assert "path=/auth/sso/oidc/callback" in set_cookie.lower()


def test_login_idp_error_redirects_to_failed():
    with patch(_MOD + ".run_db", _run_db()), \
            patch(_MOD + ".authorize_url", AsyncMock(side_effect=RuntimeError("idp down"))):
        resp = _client().get(_LOGIN, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_failed"


# ── callback: failure / CSRF paths ───────────────────────────────────────────

def test_callback_sso_disabled():
    with patch(_MOD + ".run_db", _run_db(cfg=None)):
        resp = _client().get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_disabled"


def test_callback_missing_state_cookie_fails():
    with patch(_MOD + ".run_db", _run_db()):
        resp = _client().get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    # No cookie set → cannot validate CSRF → generic failure.
    assert resp.headers["location"] == "/login?error=sso_failed"


def test_callback_missing_code_fails():
    client = _client()
    client.cookies.set(_COOKIE, "tok")
    with patch(_MOD + ".run_db", _run_db()):
        resp = client.get(_CB, params={"state": "s"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_failed"


def test_callback_state_mismatch_is_rejected():
    # The decoded cookie state must equal the query state — this is the CSRF gate.
    client = _client()
    client.cookies.set(_COOKIE, "tok")
    with patch(_MOD + ".run_db", _run_db()), \
            patch(_MOD + ".decode_state", return_value={"state": "EXPECTED", "nonce": "n"}):
        resp = client.get(_CB, params={"code": "c", "state": "ATTACKER"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_failed"


def test_callback_decode_failure_is_rejected():
    client = _client()
    client.cookies.set(_COOKIE, "tampered")
    with patch(_MOD + ".run_db", _run_db()), \
            patch(_MOD + ".decode_state", side_effect=ValueError("bad sig")):
        resp = client.get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_failed"


def test_callback_token_exchange_failure_is_rejected():
    client = _client()
    client.cookies.set(_COOKIE, "tok")
    with patch(_MOD + ".run_db", _run_db()), \
            patch(_MOD + ".decode_state", return_value={"state": "s", "nonce": "n"}), \
            patch(_MOD + ".exchange_code", AsyncMock(side_effect=RuntimeError("token error"))):
        resp = client.get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_failed"


# ── callback: success / conflict ─────────────────────────────────────────────

def test_callback_account_conflict_redirects_to_conflict():
    client = _client()
    client.cookies.set(_COOKIE, "tok")
    identity = SimpleNamespace(subject="sub-1", email="a@acme.test")
    with patch(_MOD + ".run_db", _run_db(do_ok=False)), \
            patch(_MOD + ".decode_state", return_value={"state": "s", "nonce": "n"}), \
            patch(_MOD + ".exchange_code", AsyncMock(return_value=identity)):
        resp = client.get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    assert resp.headers["location"] == "/login?error=sso_conflict"


def test_callback_success_redirects_home_and_clears_cookie():
    client = _client()
    client.cookies.set(_COOKIE, "tok")
    identity = SimpleNamespace(subject="sub-1", email="a@acme.test")
    with patch(_MOD + ".run_db", _run_db(do_ok=True)), \
            patch(_MOD + ".decode_state", return_value={"state": "s", "nonce": "n"}), \
            patch(_MOD + ".exchange_code", AsyncMock(return_value=identity)):
        resp = client.get(_CB, params={"code": "c", "state": "s"}, follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    # State cookie is cleared on success.
    assert _COOKIE in resp.headers.get("set-cookie", "")
