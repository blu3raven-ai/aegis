"""Tests for OIDC login + callback routes."""
from __future__ import annotations


def test_oidc_login_redirects_when_unconfigured(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/sso/oidc/login")
    assert resp.status_code in (302, 303, 307)
    assert "/login?error=sso_disabled" in resp.headers["location"]


def test_oidc_callback_rejects_when_unconfigured(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/sso/oidc/callback?code=x&state=y")
    assert resp.status_code in (302, 303, 307)
    assert "/login?error=sso" in resp.headers["location"]


def test_oidc_callback_rejects_bad_state(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from sqlalchemy import select
    from src.db.helpers import run_db
    from src.db.models import SsoConfig
    from src.security.crypto import encrypt

    async def _seed(session):
        row = (await session.execute(select(SsoConfig).where(SsoConfig.id == 1))).scalar_one()
        row.enabled = True
        row.protocol = "oidc"
        row.oidc_discovery_url = "https://idp.example.com/.well-known/openid-configuration"
        row.oidc_client_id = "test"
        row.oidc_client_secret_enc = encrypt("test-secret")
    run_db(_seed)

    from fastapi.testclient import TestClient
    from src.main import app
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/auth/sso/oidc/callback?code=x&state=tampered")
    assert resp.status_code in (302, 303, 307)
    location = resp.headers["location"]
    assert "sso_failed" in location or "sso_disabled" in location
