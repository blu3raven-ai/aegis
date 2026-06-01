"""Tests for the API key service layer."""
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


def _client(role: str = "owner") -> TestClient:
    from src.main import app
    import os
    os.environ["JWT_SHARED_SECRET"] = _TEST_SECRET
    token = _make_jwt(sub="svc-test", role=role)
    return TestClient(app, headers={"Authorization": f"Bearer {token}"}, raise_server_exceptions=True)


def test_token_returned_once():
    c = _client()
    resp = c.post("/api/v1/api-keys", json={
        "org_id": "svc-org",
        "name": "svc-key",
        "scopes": [],
    })
    assert resp.status_code == 201
    data = resp.json()
    assert "token" in data
    assert data["token"].startswith("ak_live_")

    list_resp = c.get("/api/v1/api-keys?org_id=svc-org")
    for key in list_resp.json()["keys"]:
        assert "token" not in key


def test_token_hash_not_in_response():
    c = _client()
    resp = c.post("/api/v1/api-keys", json={
        "org_id": "hash-org",
        "name": "hash-test",
        "scopes": [],
    })
    assert "token_hash" not in resp.json()


def test_expiry_set_correctly():
    c = _client()
    resp = c.post("/api/v1/api-keys", json={
        "org_id": "exp-org",
        "name": "exp-key",
        "scopes": [],
        "expires_in_days": 7,
    })
    assert resp.status_code == 201
    assert resp.json()["expires_at"] is not None


def test_created_by_recorded():
    c = _client()
    resp = c.post("/api/v1/api-keys", json={
        "org_id": "cb-org",
        "name": "cb-key",
        "scopes": [],
    })
    assert resp.json()["created_by"] == "svc-test"


def test_list_isolation():
    c = _client()
    c.post("/api/v1/api-keys", json={"org_id": "iso-org-1", "name": "k1", "scopes": []})
    c.post("/api/v1/api-keys", json={"org_id": "iso-org-2", "name": "k2", "scopes": []})

    resp1 = c.get("/api/v1/api-keys?org_id=iso-org-1")
    resp2 = c.get("/api/v1/api-keys?org_id=iso-org-2")

    ids1 = {k["id"] for k in resp1.json()["keys"]}
    ids2 = {k["id"] for k in resp2.json()["keys"]}
    assert ids1.isdisjoint(ids2)


def test_revoke_sets_revoked_at():
    c = _client()
    create = c.post("/api/v1/api-keys", json={
        "org_id": "rev-svc-org",
        "name": "to-revoke",
        "scopes": [],
    })
    key_id = create.json()["id"]
    resp = c.delete(f"/api/v1/api-keys/{key_id}?org_id=rev-svc-org")
    assert resp.json()["revoked_at"] is not None


def test_revoke_wrong_org_returns_404():
    c = _client()
    create = c.post("/api/v1/api-keys", json={
        "org_id": "org-correct",
        "name": "k",
        "scopes": [],
    })
    key_id = create.json()["id"]
    resp = c.delete(f"/api/v1/api-keys/{key_id}?org_id=org-wrong")
    assert resp.status_code == 404


def test_revoke_nonexistent_returns_404():
    c = _client()
    resp = c.delete("/api/v1/api-keys/8888888?org_id=example-org")
    assert resp.status_code == 404


def test_no_expiry_key():
    c = _client()
    resp = c.post("/api/v1/api-keys", json={
        "org_id": "no-exp-org",
        "name": "no-exp",
        "scopes": [],
    })
    assert resp.json()["expires_at"] is None


def test_record_usage_does_not_raise():
    from src.api_keys.service import _record_usage_sync
    _record_usage_sync(999999999)
