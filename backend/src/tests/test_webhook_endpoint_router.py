"""Tests for the per-org webhook endpoints CRUD router."""
from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.settings.webhooks.router import router as webhook_endpoints_router  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import WebhookEndpoint  # noqa: E402
from src.shared.encryption import decrypt  # noqa: E402

_ADMIN_PERMS = {"manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app(*, allow_manage_settings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(webhook_endpoints_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_settings:
        app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return app


@pytest.fixture(autouse=True)
def _disable_audit():
    prev = os.environ.get("AEGIS_AUDIT_LOG_ENABLED")
    os.environ["AEGIS_AUDIT_LOG_ENABLED"] = "false"
    yield
    if prev is None:
        del os.environ["AEGIS_AUDIT_LOG_ENABLED"]
    else:
        os.environ["AEGIS_AUDIT_LOG_ENABLED"] = prev


@pytest.fixture(autouse=True)
def _cleanup_webhook_endpoints():
    yield

    async def _q(session: AsyncSession) -> None:
        await session.execute(delete(WebhookEndpoint))

    run_db(_q)


def test_create_returns_secret_once_and_masked_thereafter():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/settings/webhooks", json={"provider": "github"})
        assert resp.status_code == 201
        body = resp.json()
        secret = body["secret"]
        assert len(secret) >= 32
        assert body["last4"] == secret[-4:]


def test_create_persists_encrypted_secret():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/settings/webhooks", json={"provider": "gitlab"})
        secret = resp.json()["secret"]

        async def _q(session: AsyncSession) -> tuple[str, str]:
            row = (
                await session.execute(
                    select(WebhookEndpoint).where(WebhookEndpoint.provider == "gitlab")
                )
            ).scalar_one()
            return row.secret_enc, row.provider

        secret_enc, provider = run_db(_q)
        assert secret_enc != secret
        assert secret_enc.startswith("v2:")
        decrypted = decrypt(secret_enc, context=f"webhook_endpoint:{provider}")
        assert decrypted == secret


def test_create_duplicate_returns_409():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        first = client.post("/api/v1/settings/webhooks", json={"provider": "github"})
        assert first.status_code == 201

        second = client.post("/api/v1/settings/webhooks", json={"provider": "github"})
        assert second.status_code == 409


def test_create_rejects_unknown_provider():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/settings/webhooks", json={"provider": "perforce"}
        )
        assert resp.status_code == 422


def test_rotate_changes_stored_secret_and_returns_new_value_once():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        created = client.post(
            "/api/v1/settings/webhooks", json={"provider": "bitbucket"}
        ).json()
        old_secret = created["secret"]
        endpoint_id = created["id"]

        rotate_resp = client.post(f"/api/v1/settings/webhooks/{endpoint_id}/rotate")
        assert rotate_resp.status_code == 200
        new_payload = rotate_resp.json()
        new_secret = new_payload["secret"]
        assert new_secret != old_secret
        assert new_payload["last4"] == new_secret[-4:]
        assert new_payload["rotatedAt"] is not None

        async def _q(session: AsyncSession) -> str:
            row = (
                await session.execute(
                    select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id)
                )
            ).scalar_one()
            return decrypt(row.secret_enc, context=f"webhook_endpoint:{row.provider}")

        assert run_db(_q) == new_secret


def test_rotate_unknown_endpoint_returns_404():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/settings/webhooks/does-not-exist/rotate")
        assert resp.status_code == 404


def test_delete_removes_row():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        created = client.post(
            "/api/v1/settings/webhooks", json={"provider": "jenkins"}
        ).json()
        endpoint_id = created["id"]

        del_resp = client.delete(f"/api/v1/settings/webhooks/{endpoint_id}")
        assert del_resp.status_code == 204

        async def _q(session: AsyncSession) -> int:
            rows = (
                await session.execute(
                    select(WebhookEndpoint).where(WebhookEndpoint.id == endpoint_id)
                )
            ).scalars().all()
            return len(rows)

        assert run_db(_q) == 0


def test_delete_unknown_returns_404():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_ADMIN_PERMS):
        client = TestClient(_make_app())
        resp = client.delete("/api/v1/settings/webhooks/missing")
        assert resp.status_code == 404


def test_non_admin_forbidden():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False):
        client = TestClient(_make_app(allow_manage_settings=False))
        assert client.post(
            "/api/v1/settings/webhooks", json={"provider": "github"}
        ).status_code == 403
        assert client.post(
            "/api/v1/settings/webhooks/x/rotate"
        ).status_code == 403
        assert client.delete("/api/v1/settings/webhooks/x").status_code == 403
