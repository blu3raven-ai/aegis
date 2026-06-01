"""Tests for the API key CRUD router."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session", autouse=True)
def _seed_roles():
    """Ensure default roles exist in the test DB."""
    from src.db.helpers import run_db
    from src.db.models import Role
    from src.db.seed import DEFAULT_ROLES
    from datetime import datetime, timezone

    async def _insert(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data["protected"],
                    created_at=datetime.now(timezone.utc),
                ))

    run_db(_insert)


_TEST_SECRET = "a" * 64


def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _make_jwt(sub: str, role: str, secret: str = _TEST_SECRET) -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload = _b64url(json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + 60}))
    key = bytes.fromhex(secret)
    sig = _b64url(hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def _make_client(role: str = "owner") -> TestClient:
    from src.main import app
    import os
    os.environ["JWT_SHARED_SECRET"] = _TEST_SECRET
    token = _make_jwt(sub=f"usr_{role}", role=role)
    return TestClient(app, headers={"Authorization": f"Bearer {token}"}, raise_server_exceptions=True)


def test_create_api_key():
    client = _make_client()
    resp = client.post("/api/v1/api-keys", json={
        "org_id": "example-org",
        "name": "ci-key",
        "scopes": ["read:findings"],
        "expires_in_days": 30,
    })
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "ci-key"
    assert data["token"].startswith("ak_live_")
    assert "token_hash" not in data


def test_create_returns_token_once():
    client = _make_client()
    resp = client.post("/api/v1/api-keys", json={
        "org_id": "example-org",
        "name": "one-time-token",
        "scopes": [],
    })
    assert resp.status_code == 201
    token = resp.json()["token"]
    assert len(token) > 8


def test_list_api_keys():
    client = _make_client()
    client.post("/api/v1/api-keys", json={
        "org_id": "list-org",
        "name": "list-test",
        "scopes": [],
    })
    resp = client.get("/api/v1/api-keys?org_id=list-org")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1


def test_list_excludes_other_org():
    client = _make_client()
    client.post("/api/v1/api-keys", json={
        "org_id": "org-a",
        "name": "key-for-a",
        "scopes": [],
    })
    resp = client.get("/api/v1/api-keys?org_id=org-b-unique")
    assert resp.status_code == 200
    assert resp.json()["keys"] == []


def test_revoke_api_key():
    client = _make_client()
    create_resp = client.post("/api/v1/api-keys", json={
        "org_id": "revoke-org",
        "name": "to-revoke",
        "scopes": [],
    })
    key_id = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/api-keys/{key_id}?org_id=revoke-org")
    assert resp.status_code == 200
    assert resp.json()["revoked_at"] is not None


def test_revoke_wrong_org_returns_404():
    client = _make_client()
    create_resp = client.post("/api/v1/api-keys", json={
        "org_id": "org-x",
        "name": "key-x",
        "scopes": [],
    })
    key_id = create_resp.json()["id"]
    resp = client.delete(f"/api/v1/api-keys/{key_id}?org_id=wrong-org")
    assert resp.status_code == 404


def test_revoke_nonexistent_returns_404():
    client = _make_client()
    resp = client.delete("/api/v1/api-keys/9999999?org_id=example-org")
    assert resp.status_code == 404


def test_viewer_cannot_create():
    client = _make_client(role="viewer")
    resp = client.post("/api/v1/api-keys", json={
        "org_id": "example-org",
        "name": "blocked",
        "scopes": [],
    })
    assert resp.status_code == 403


def test_viewer_cannot_list():
    client = _make_client(role="viewer")
    resp = client.get("/api/v1/api-keys?org_id=example-org")
    assert resp.status_code == 403


def test_viewer_cannot_revoke():
    owner_client = _make_client(role="owner")
    create_resp = owner_client.post("/api/v1/api-keys", json={
        "org_id": "viewer-test-org",
        "name": "viewer-cant-revoke",
        "scopes": [],
    })
    key_id = create_resp.json()["id"]

    viewer_client = _make_client(role="viewer")
    resp = viewer_client.delete(f"/api/v1/api-keys/{key_id}?org_id=viewer-test-org")
    assert resp.status_code == 403


def test_no_expiry():
    client = _make_client()
    resp = client.post("/api/v1/api-keys", json={
        "org_id": "example-org",
        "name": "no-expiry",
        "scopes": [],
        "expires_in_days": None,
    })
    assert resp.status_code == 201
    assert resp.json()["expires_at"] is None
