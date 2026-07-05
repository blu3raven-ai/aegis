"""Router-layer coverage for the per-channel webhook signing-secret endpoints.

These rotate/revoke HMAC secrets, so two things must hold: the manage_settings
gate on every verb, and the webhook-only guard (signing secrets are meaningless
for an email destination). The raw secret is returned exactly once on creation.
Service mocked; only the router layer is pinned.
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

from src.settings.notifications.signing_router import router as signing_router

_BASE = "/api/v1/notifications/destinations"
_MOD = "src.settings.notifications.signing_router"
_PATCH = "src.authz.enforcement.dependencies.has_role_permission"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(signing_router)

    @app.middleware("http")
    async def _inject_state(request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.user_org = "acme-org"
        return await call_next(request)

    return app


def _client() -> TestClient:
    return TestClient(_make_app())


def _allow(*_a, **_k):
    return True


def _deny(*_a, **_k):
    return False


_WEBHOOK = {"id": 1, "destination_type": "webhook"}


# ── permission gate ──────────────────────────────────────────────────────────

def test_list_403_without_manage_settings():
    with patch(_PATCH, _deny):
        assert _client().get(f"{_BASE}/1/signing-secret").status_code == 403


def test_rotate_403_without_manage_settings():
    with patch(_PATCH, _deny):
        assert _client().post(f"{_BASE}/1/signing-secret").status_code == 403


# ── webhook-only destination guard ───────────────────────────────────────────

def test_404_when_destination_missing():
    with patch(_PATCH, _allow), patch(f"{_MOD}.get_destination", return_value=None):
        resp = _client().get(f"{_BASE}/9/signing-secret")
    assert resp.status_code == 404


def test_422_for_non_webhook_destination():
    with patch(_PATCH, _allow), \
            patch(f"{_MOD}.get_destination", return_value={"id": 2, "destination_type": "email"}):
        resp = _client().get(f"{_BASE}/2/signing-secret")
    assert resp.status_code == 422


# ── list ─────────────────────────────────────────────────────────────────────

def test_list_returns_versions():
    with patch(_PATCH, _allow), patch(f"{_MOD}.get_destination", return_value=_WEBHOOK), \
            patch(f"{_MOD}.list_signing_secrets", return_value=[{"version": 1, "status": "active"}]):
        resp = _client().get(f"{_BASE}/1/signing-secret")
    assert resp.status_code == 200
    assert resp.json() == {"secrets": [{"version": 1, "status": "active"}]}


# ── rotate (create) ──────────────────────────────────────────────────────────

def test_rotate_returns_raw_once_and_persists():
    meta = {"version": 3, "status": "active"}
    with patch(_PATCH, _allow), patch(f"{_MOD}.get_destination", return_value=_WEBHOOK), \
            patch(f"{_MOD}.create_signing_secret", return_value=(meta, "RAWSECRET")) as create, \
            patch(f"{_MOD}.persist_raw_secret_to_channel") as persist:
        resp = _client().post(f"{_BASE}/1/signing-secret")
    assert resp.status_code == 201
    body = resp.json()
    assert body["secret"]["raw"] == "RAWSECRET"
    assert body["secret"]["version"] == 3
    assert body["signing_secret_version"] == 3
    assert "not be shown again" in body["notice"]
    # Raw is persisted to the channel config for outbound signing.
    assert persist.call_args.args == (1, 3, "RAWSECRET")
    assert create.called


# ── revoke ───────────────────────────────────────────────────────────────────

def test_revoke_404_for_unknown_version():
    with patch(_PATCH, _allow), patch(f"{_MOD}.get_destination", return_value=_WEBHOOK), \
            patch(f"{_MOD}.revoke_signing_secret_version", return_value=None):
        resp = _client().delete(f"{_BASE}/1/signing-secret/99")
    assert resp.status_code == 404


def test_revoke_ok_and_clears_channel():
    meta = {"version": 2, "status": "revoked"}
    with patch(_PATCH, _allow), patch(f"{_MOD}.get_destination", return_value=_WEBHOOK), \
            patch(f"{_MOD}.revoke_signing_secret_version", return_value=meta), \
            patch(f"{_MOD}.revoke_raw_secret_in_channel") as clear:
        resp = _client().delete(f"{_BASE}/1/signing-secret/2")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "revoked": meta}
    assert clear.call_args.args == (1, 2)
