"""Tests for the Phase 42 notification rules REST endpoints.

Uses the full app (same pattern as test_api_key_router.py) so that auth
middleware, DB fixtures, and router registration are all exercised together.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete

_TEST_SECRET = "a" * 64
_ORG = "example-org"


# ── Auth helpers ──────────────────────────────────────────────────────────────


def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _make_jwt(sub: str = "usr_owner", role: str = "owner") -> str:
    now = int(time.time())
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}))
    payload_data = json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + 60})
    payload = _b64url(payload_data)
    key = bytes.fromhex(_TEST_SECRET)
    sig = _b64url(hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="session", autouse=True)
def _seed_roles():
    """Ensure default roles exist (mirrors test_api_key_router.py fixture)."""
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


@pytest.fixture(autouse=True)
def _clean_rules():
    """Remove all notification rules and destinations before each test."""
    from src.db.helpers import run_db
    from src.db.models import NotificationRule, NotificationDestination

    async def _del(session):
        await session.execute(delete(NotificationRule))
        await session.execute(delete(NotificationDestination))

    run_db(_del)
    yield
    run_db(_del)


@pytest.fixture
def client() -> TestClient:
    os.environ["JWT_SHARED_SECRET"] = _TEST_SECRET
    from src.main import app
    token = _make_jwt()
    return TestClient(app, headers={"Authorization": f"Bearer {token}"}, raise_server_exceptions=True)


# ── Helper to create a destination for FK ────────────────────────────────────


def _create_dest(client: TestClient, name: str = "test-dest") -> int:
    resp = client.post(
        "/api/v1/notifications/destinations",
        json={
            "org_id": _ORG,
            "destination_type": "webhook",
            "name": name,
            "config": {"url": "https://example.com/hook"},
            "enabled": True,
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


# ── list ──────────────────────────────────────────────────────────────────────


def test_list_empty(client: TestClient):
    resp = client.get(f"/api/v1/notification-rules?org_id={_ORG}")
    assert resp.status_code == 200
    assert resp.json() == {"rules": []}


# ── create ────────────────────────────────────────────────────────────────────


def test_create_rule(client: TestClient):
    channel_id = _create_dest(client)
    resp = client.post(
        "/api/v1/notification-rules",
        json={
            "org_id": _ORG,
            "name": "crits to sec-channel",
            "channel_id": channel_id,
            "priority": 10,
            "enabled": True,
            "conditions": {"field": "severity", "op": "eq", "value": "critical"},
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "crits to sec-channel"
    assert data["priority"] == 10
    assert data["channel_id"] == channel_id
    assert data["enabled"] is True
    assert data["id"].startswith("nr_")


def test_create_rule_appears_in_list(client: TestClient):
    channel_id = _create_dest(client)
    client.post(
        "/api/v1/notification-rules",
        json={
            "org_id": _ORG,
            "name": "rule-list-test",
            "channel_id": channel_id,
            "conditions": {},
        },
    )
    resp = client.get(f"/api/v1/notification-rules?org_id={_ORG}")
    assert resp.status_code == 200
    rules = resp.json()["rules"]
    assert len(rules) == 1
    assert rules[0]["name"] == "rule-list-test"


# ── get by id ─────────────────────────────────────────────────────────────────


def test_get_rule(client: TestClient):
    channel_id = _create_dest(client)
    created = client.post(
        "/api/v1/notification-rules",
        json={"org_id": _ORG, "name": "get-test", "channel_id": channel_id, "conditions": {}},
    ).json()

    resp = client.get(f"/api/v1/notification-rules/{created['id']}?org_id={_ORG}")
    assert resp.status_code == 200
    assert resp.json()["id"] == created["id"]


def test_get_rule_not_found(client: TestClient):
    resp = client.get(f"/api/v1/notification-rules/nr_nonexistent?org_id={_ORG}")
    assert resp.status_code == 404


# ── update ────────────────────────────────────────────────────────────────────


def test_update_rule(client: TestClient):
    channel_id = _create_dest(client)
    created = client.post(
        "/api/v1/notification-rules",
        json={"org_id": _ORG, "name": "original-name", "channel_id": channel_id, "conditions": {}},
    ).json()

    resp = client.put(
        f"/api/v1/notification-rules/{created['id']}?org_id={_ORG}",
        json={"name": "updated-name", "priority": 5},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "updated-name"
    assert data["priority"] == 5


def test_update_rule_not_found(client: TestClient):
    resp = client.put(
        f"/api/v1/notification-rules/nr_nonexistent?org_id={_ORG}",
        json={"name": "x"},
    )
    assert resp.status_code == 404


# ── delete ────────────────────────────────────────────────────────────────────


def test_delete_rule(client: TestClient):
    channel_id = _create_dest(client)
    created = client.post(
        "/api/v1/notification-rules",
        json={"org_id": _ORG, "name": "to-delete", "channel_id": channel_id, "conditions": {}},
    ).json()

    resp = client.delete(f"/api/v1/notification-rules/{created['id']}?org_id={_ORG}")
    assert resp.status_code == 204

    # Confirm gone
    get_resp = client.get(f"/api/v1/notification-rules/{created['id']}?org_id={_ORG}")
    assert get_resp.status_code == 404


def test_delete_rule_not_found(client: TestClient):
    resp = client.delete(f"/api/v1/notification-rules/nr_nonexistent?org_id={_ORG}")
    assert resp.status_code == 404


# ── preview: single rule ──────────────────────────────────────────────────────


def test_preview_single_rule_match(client: TestClient):
    channel_id = _create_dest(client)
    resp = client.post(
        "/api/v1/notification-rules/preview",
        json={
            "rule": {
                "org_id": _ORG,
                "name": "crits rule",
                "channel_id": channel_id,
                "conditions": {"field": "severity", "op": "eq", "value": "critical"},
            },
            "finding": {"severity": "critical", "scanner": "secrets", "repo_id": "r1"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is True
    assert data["channel_id"] == channel_id


def test_preview_single_rule_no_match(client: TestClient):
    channel_id = _create_dest(client)
    resp = client.post(
        "/api/v1/notification-rules/preview",
        json={
            "rule": {
                "org_id": _ORG,
                "name": "crits only",
                "channel_id": channel_id,
                "conditions": {"field": "severity", "op": "eq", "value": "critical"},
            },
            "finding": {"severity": "low", "scanner": "dependencies", "repo_id": "r1"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["matched"] is False
    assert data["channel_id"] is None


# ── preview: full org evaluation ─────────────────────────────────────────────


def test_preview_org_evaluation(client: TestClient):
    channel_id = _create_dest(client)
    # Seed a rule
    client.post(
        "/api/v1/notification-rules",
        json={
            "org_id": _ORG,
            "name": "high+",
            "channel_id": channel_id,
            "priority": 10,
            "conditions": {"field": "severity", "op": "in", "value": ["critical", "high"]},
        },
    )

    resp = client.post(
        "/api/v1/notification-rules/preview",
        json={
            "org_id": _ORG,
            "finding": {"severity": "high", "scanner": "code_scanning", "repo_id": "repo-abc"},
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert channel_id in data["matched_channel_ids"]
    assert len(data["breakdown"]) == 1
    assert data["breakdown"][0]["matched"] is True


def test_preview_missing_params_raises_422(client: TestClient):
    resp = client.post(
        "/api/v1/notification-rules/preview",
        json={"finding": {"severity": "high", "scanner": "x", "repo_id": "y"}},
    )
    assert resp.status_code == 422


# ── list ordering by priority ─────────────────────────────────────────────────


def test_list_rules_ordered_by_priority(client: TestClient):
    channel_id = _create_dest(client)
    for prio, name in [(30, "rule-30"), (10, "rule-10"), (20, "rule-20")]:
        client.post(
            "/api/v1/notification-rules",
            json={"org_id": _ORG, "name": name, "channel_id": channel_id, "priority": prio, "conditions": {}},
        )
    rules = client.get(f"/api/v1/notification-rules?org_id={_ORG}").json()["rules"]
    assert [r["name"] for r in rules] == ["rule-10", "rule-20", "rule-30"]
