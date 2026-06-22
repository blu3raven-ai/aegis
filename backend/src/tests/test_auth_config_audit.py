"""Audit emission tests for SSO and SCIM config mutations.

These endpoints control identity-provider settings and SCIM bearer tokens —
tampering here is a persistent backdoor or credential-lifecycle event.
The @audited decorator is applied at the router; these tests pin the
action name + resource_type + actor for each endpoint.
"""
from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.settings.scim.router import scim_settings_router  # noqa: E402
from src.settings.sso.router import sso_router  # noqa: E402


_ADMIN_PERMS = {"manage_settings"}


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def record(self, *, action, resource_type, resource_id=None, actor=None, **_):
        self.calls.append({
            "action": action,
            "resource_type": resource_type,
            "actor_user_id": getattr(actor, "user_id", None),
        })


def _make_app(router) -> FastAPI:
    app = FastAPI()
    app.include_router(router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


def _patch_admin_perms_and_recorder(rec):
    return [
        patch("src.authz.enforcement._resolve_effective_permissions",
              return_value=_ADMIN_PERMS),
        patch("src.audit_log.recorder.get_recorder", return_value=rec),
    ]


# ─── SSO ──────────────────────────────────────────────────────────────────────


def test_patch_sso_records_sso_config_updated():
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.sso.router.run_db",
               return_value={"enabled": True, "protocol": "saml"}):
        client = TestClient(_make_app(sso_router))
        resp = client.patch("/api/v1/settings/sso", json={"enabled": True, "protocol": "saml"})

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "sso.config_updated"
    assert rec.calls[0]["resource_type"] == "sso_config"
    assert rec.calls[0]["actor_user_id"] == "user-1"


def test_post_saml_sp_keypair_records_sso_saml_keypair_generated():
    """Generating a fresh SP keypair invalidates SAML signatures from previous
    IdP integrations until the IdP refreshes. High-impact admin action."""
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.sso.router.run_db",
               return_value={"certificate": "...", "updatedAt": "2026-06-19T00:00:00Z"}):
        client = TestClient(_make_app(sso_router))
        resp = client.post("/api/v1/settings/sso/saml/sp-keypair")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "sso.saml_keypair_generated"


def test_post_refresh_metadata_records_sso_saml_metadata_refreshed():
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.sso.router.run_db",
               return_value={"ok": True}):
        client = TestClient(_make_app(sso_router))
        resp = client.post("/api/v1/settings/sso/saml/refresh-metadata")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "sso.saml_metadata_refreshed"


# ─── SCIM ─────────────────────────────────────────────────────────────────────


def test_patch_scim_records_scim_config_updated():
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.scim.router.run_db",
               return_value={"enabled": True}):
        client = TestClient(_make_app(scim_settings_router))
        resp = client.patch("/api/v1/settings/scim", json={"enabled": True})

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "scim.config_updated"
    assert rec.calls[0]["resource_type"] == "scim_config"


def test_post_scim_token_records_scim_token_generated():
    """SCIM bearer tokens are durable credentials that authorize the provisioning
    API to create/disable users. Mints are a credential-lifecycle event."""
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.scim.router.run_db",
               return_value={"token": "raw-tok", "updatedAt": "2026-06-19T00:00:00Z"}):
        client = TestClient(_make_app(scim_settings_router))
        resp = client.post("/api/v1/settings/scim/token")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "scim.token_generated"


def test_delete_scim_token_records_scim_token_revoked():
    rec = _Recorder()
    with _patch_admin_perms_and_recorder(rec)[0], \
         _patch_admin_perms_and_recorder(rec)[1], \
         patch("src.settings.scim.router.run_db",
               return_value={"enabled": True, "tokenSet": False}):
        client = TestClient(_make_app(scim_settings_router))
        resp = client.delete("/api/v1/settings/scim/token")

    assert resp.status_code == 200
    assert len(rec.calls) == 1
    assert rec.calls[0]["action"] == "scim.token_revoked"
