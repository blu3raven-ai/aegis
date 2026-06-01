"""Tests for the Phase 44 webhook signing secrets REST endpoints.

Exercises the full CRUD + rotation flow via the FastAPI test client.
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
    payload_b = _b64url(payload_data)
    key = bytes.fromhex(_TEST_SECRET)
    sig = _b64url(hmac.new(key, f"{header}.{payload_b}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload_b}.{sig}"


def _client(role: str = "owner") -> TestClient:
    from src.main import app
    os.environ["JWT_SHARED_SECRET"] = _TEST_SECRET
    token = _make_jwt(role=role)
    return TestClient(app, headers={"Authorization": f"Bearer {token}"}, raise_server_exceptions=True)


# ── Fixtures ──────────────────────────────────────────────────────────────────

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


@pytest.fixture()
def webhook_dest_id() -> int:
    """Create a fresh webhook destination for each test."""
    from src.notifications.destination import create_destination
    dest = create_destination(
        org_id=_ORG,
        destination_type="webhook",
        name=f"test-wh-{time.time_ns()}",
        config={"url": "https://example.org/hook"},
    )
    return dest["id"]


@pytest.fixture()
def email_dest_id() -> int:
    """Email destination — should be rejected by signing endpoints."""
    from src.notifications.destination import create_destination
    dest = create_destination(
        org_id=_ORG,
        destination_type="email",
        name=f"test-email-{time.time_ns()}",
        config={"to_addresses": ["sec@example.org"]},
    )
    return dest["id"]


# ── GET /signing-secret ───────────────────────────────────────────────────────

class TestListSecrets:
    def test_empty_list_for_new_channel(self, webhook_dest_id):
        c = _client()
        resp = c.get(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        assert resp.status_code == 200
        assert resp.json()["secrets"] == []

    def test_lists_metadata_only(self, webhook_dest_id):
        c = _client()
        # Create a secret first
        c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        resp = c.get(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        assert resp.status_code == 200
        secrets = resp.json()["secrets"]
        assert len(secrets) == 1
        s = secrets[0]
        assert "raw" not in s
        assert "secret_hash" not in s
        assert "version" in s
        assert "status" in s

    def test_404_for_nonexistent_destination(self):
        c = _client()
        resp = c.get("/api/v1/notification-channels/999999/signing-secret")
        assert resp.status_code == 404

    def test_422_for_non_webhook_destination(self, email_dest_id):
        c = _client()
        resp = c.get(f"/api/v1/notification-channels/{email_dest_id}/signing-secret")
        assert resp.status_code == 422


# ── POST /signing-secret (rotation) ──────────────────────────────────────────

class TestRotateSecret:
    def test_returns_raw_secret_once(self, webhook_dest_id):
        c = _client()
        resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        assert resp.status_code == 201
        body = resp.json()
        assert "raw" in body["secret"]
        assert len(body["secret"]["raw"]) >= 40

    def test_raw_not_in_subsequent_list(self, webhook_dest_id):
        c = _client()
        c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        resp = c.get(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        for s in resp.json()["secrets"]:
            assert "raw" not in s

    def test_version_increments_on_rotation(self, webhook_dest_id):
        c = _client()
        r1 = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret").json()
        r2 = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret").json()
        assert r2["signing_secret_version"] == r1["signing_secret_version"] + 1

    def test_old_key_demoted_to_rotating(self, webhook_dest_id):
        c = _client()
        c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        resp = c.get(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        secrets = resp.json()["secrets"]
        statuses = {s["version"]: s["status"] for s in secrets}
        assert statuses[2] == "active"
        assert statuses[1] == "rotating"

    def test_notice_included_in_response(self, webhook_dest_id):
        c = _client()
        resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        assert "notice" in resp.json()

    def test_viewer_cannot_rotate(self, webhook_dest_id):
        c = _client(role="viewer")
        resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        assert resp.status_code in (403, 401)


# ── DELETE /signing-secret/{version} ─────────────────────────────────────────

class TestRevokeVersion:
    def test_revoke_marks_revoked_status(self, webhook_dest_id):
        c = _client()
        create_resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret").json()
        version = create_resp["signing_secret_version"]

        resp = c.delete(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret/{version}")
        assert resp.status_code == 200
        assert resp.json()["revoked"]["status"] == "revoked"
        assert resp.json()["revoked"]["revoked_at"] is not None

    def test_list_shows_revoked_status(self, webhook_dest_id):
        c = _client()
        create_resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret").json()
        version = create_resp["signing_secret_version"]
        c.delete(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret/{version}")

        resp = c.get(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret")
        s = next(x for x in resp.json()["secrets"] if x["version"] == version)
        assert s["status"] == "revoked"

    def test_revoke_nonexistent_version_returns_404(self, webhook_dest_id):
        c = _client()
        resp = c.delete(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret/999")
        assert resp.status_code == 404

    def test_viewer_cannot_revoke(self, webhook_dest_id):
        c = _client()
        create_resp = c.post(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret").json()
        version = create_resp["signing_secret_version"]
        viewer = _client(role="viewer")
        resp = viewer.delete(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret/{version}")
        assert resp.status_code in (403, 401)


# ── Full rotation flow ────────────────────────────────────────────────────────

class TestRotationFlow:
    def test_full_rotation_and_verification(self, webhook_dest_id):
        """Generate secret, sign a payload, verify the signed headers work."""
        c = _client()
        create_resp = c.post(
            f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret"
        ).json()
        raw = create_resp["secret"]["raw"]
        version = create_resp["signing_secret_version"]

        # Build headers manually to simulate what the sender would do
        from src.notifications.webhook_signing import build_signing_headers, verify_signature
        payload = {"event_type": "finding.created", "severity": "critical"}
        headers = build_signing_headers(payload, [raw])

        ts_str = headers["X-Aegis-Timestamp"]
        all_sigs = headers["X-Aegis-Signature"].split(",")
        assert any(verify_signature(payload, raw, ts_str, sig) for sig in all_sigs)

    def test_revoked_secret_not_in_active_raws(self, webhook_dest_id):
        from src.notifications.webhook_signing import get_raw_secrets_for_channel
        c = _client()
        create_resp = c.post(
            f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret"
        ).json()
        raw = create_resp["secret"]["raw"]
        version = create_resp["signing_secret_version"]

        assert raw in get_raw_secrets_for_channel(webhook_dest_id)

        c.delete(f"/api/v1/notification-channels/{webhook_dest_id}/signing-secret/{version}")
        assert raw not in get_raw_secrets_for_channel(webhook_dest_id)
