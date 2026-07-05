"""Tests for the auth-security policy router.

The GET handler moved to GraphQL (covered by test_graphql_auth_settings.py).
This file covers the PATCH handler that remains on REST.
"""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.settings.auth_security.router import auth_security_router

_ADMIN_PERMS = {"manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(auth_security_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def test_patch_writes_config_and_returns_ok_for_admin():
    captured: dict = {}

    def _capture_write(config, event_type):
        captured["config"] = config
        captured["event_type"] = event_type

    body = {
        "requireMfaManualUsers": True,
        "requireMfaAdmins": False,
        "trustedSessionDurationDays": 21,
        "recoveryCodePolicy": "mandatory",
    }
    with (
        patch(
            "src.settings.auth_security.router.read_app_config",
            return_value={},
        ),
        patch(
            "src.settings.auth_security.router.write_app_config",
            side_effect=_capture_write,
        ),
        patch(
            "src.settings.auth_security.router.sync_runtime_env_from_config",
        ),
    ):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/settings/auth-security", json=body)

    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert captured["config"]["authSecurity"] == body
    assert captured["event_type"] == "settings.auth_security.updated"


def test_patch_rejects_non_admin_with_403():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_manage_settings=False))
        resp = client.patch(
            "/api/v1/settings/auth-security",
            json={
                "requireMfaManualUsers": True,
                "requireMfaAdmins": True,
                "trustedSessionDurationDays": 14,
                "recoveryCodePolicy": "optional",
            },
        )
    assert resp.status_code == 403


# ─── Audit emission ───────────────────────────────────────────────────────────


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, *, action, resource_type, resource_id=None, actor=None, **_):
        self.calls.append({
            "action": action,
            "resource_type": resource_type,
            "actor_user_id": getattr(actor, "user_id", None),
        })


def test_patch_auth_security_records_audit_event():
    """Auth-security policy controls MFA + session duration. Changes here
    weaken or harden the entire login surface and need a compliance trail."""
    rec = _Recorder()
    with patch("src.authz.enforcement._resolve_effective_permissions",
               return_value=_ADMIN_PERMS), \
         patch("src.audit_log.recorder.get_recorder", return_value=rec), \
         patch("src.settings.auth_security.router.read_app_config",
               return_value={"authSecurity": {}}), \
         patch("src.settings.auth_security.router.write_app_config"), \
         patch("src.settings.auth_security.router.sync_runtime_env_from_config"):
        client = TestClient(_make_app())
        resp = client.patch(
            "/api/v1/settings/auth-security",
            json={
                "requireMfaManualUsers": True,
                "requireMfaAdmins": True,
                "trustedSessionDurationDays": 14,
                "recoveryCodePolicy": "mandatory",
            },
        )

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "auth_security.config_updated"
    assert rec.calls[0]["resource_type"] == "auth_security_config"
    assert rec.calls[0]["actor_user_id"] == "user-1"
