"""Unit tests for webhook_signing module.

Tests cover: sign/verify roundtrip, timestamp tolerance, multi-secret
verification, tamper detection, header builder, and DB helpers.
All DB operations are exercised with the testcontainer Postgres fixture.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.notifications.webhook_signing import (
    TOLERANCE_SECONDS,
    _generate_secret,
    _hash_secret,
    build_signing_headers,
    sign_payload,
    verify_signature,
)


# ── sign_payload ──────────────────────────────────────────────────────────────

class TestSignPayload:
    def test_returns_tuple_of_ts_and_sig(self):
        ts_str, sig = sign_payload({"event": "test"}, "mysecret")
        assert isinstance(ts_str, str)
        assert sig.startswith("v1=")

    def test_deterministic_with_fixed_timestamp(self):
        payload = {"a": 1, "b": "x"}
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        _, sig1 = sign_payload(payload, "secret", ts)
        _, sig2 = sign_payload(payload, "secret", ts)
        assert sig1 == sig2

    def test_different_secret_different_signature(self):
        payload = {"event": "chain.created"}
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        _, sig1 = sign_payload(payload, "secret-a", ts)
        _, sig2 = sign_payload(payload, "secret-b", ts)
        assert sig1 != sig2

    def test_uses_canonical_json_ordering(self):
        ts = datetime(2025, 1, 1, tzinfo=timezone.utc)
        ts_str = str(int(ts.timestamp()))
        payload = {"z": 99, "a": 1}
        _, sig = sign_payload(payload, "key", ts)
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        signed = f"{ts_str}.{canonical}".encode()
        expected_hex = hmac.new("key".encode(), signed, hashlib.sha256).hexdigest()
        assert sig == f"v1={expected_hex}"

    def test_timestamp_str_is_unix_seconds(self):
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        ts_str, _ = sign_payload({}, "s", ts)
        assert ts_str == str(int(ts.timestamp()))


# ── verify_signature ──────────────────────────────────────────────────────────

class TestVerifySignature:
    def _sign_now(self, payload, secret):
        ts = datetime.now(timezone.utc)
        ts_str, sig = sign_payload(payload, secret, ts)
        return ts_str, sig

    def test_valid_signature_returns_true(self):
        payload = {"event": "finding.created", "severity": "critical"}
        ts_str, sig = self._sign_now(payload, "mysecret")
        assert verify_signature(payload, "mysecret", ts_str, sig)

    def test_wrong_secret_returns_false(self):
        payload = {"event": "finding.created"}
        ts_str, sig = self._sign_now(payload, "correct-secret")
        assert not verify_signature(payload, "wrong-secret", ts_str, sig)

    def test_tampered_payload_returns_false(self):
        payload = {"event": "finding.created", "severity": "low"}
        ts_str, sig = self._sign_now(payload, "sec")
        tampered = {**payload, "severity": "critical"}
        assert not verify_signature(tampered, "sec", ts_str, sig)

    def test_expired_timestamp_returns_false(self):
        payload = {"event": "scan.complete"}
        old_ts = int(time.time()) - TOLERANCE_SECONDS - 10
        ts_str = str(old_ts)
        ts_dt = datetime.fromtimestamp(old_ts, tz=timezone.utc)
        _, sig = sign_payload(payload, "sec", ts_dt)
        assert not verify_signature(payload, "sec", ts_str, sig)

    def test_future_timestamp_within_tolerance_returns_true(self):
        payload = {"event": "test"}
        future = int(time.time()) + TOLERANCE_SECONDS - 10
        ts_str = str(future)
        ts_dt = datetime.fromtimestamp(future, tz=timezone.utc)
        _, sig = sign_payload(payload, "sec", ts_dt)
        assert verify_signature(payload, "sec", ts_str, sig)

    def test_malformed_timestamp_returns_false(self):
        payload = {"x": 1}
        assert not verify_signature(payload, "sec", "not-a-number", "v1=abc")

    def test_custom_tolerance(self):
        payload = {"event": "x"}
        old_ts = int(time.time()) - 10
        ts_str = str(old_ts)
        ts_dt = datetime.fromtimestamp(old_ts, tz=timezone.utc)
        _, sig = sign_payload(payload, "sec", ts_dt)
        # tolerance of 5s: 10s old should fail
        assert not verify_signature(payload, "sec", ts_str, sig, tolerance_seconds=5)
        # tolerance of 60s: 10s old should pass
        assert verify_signature(payload, "sec", ts_str, sig, tolerance_seconds=60)


# ── build_signing_headers ─────────────────────────────────────────────────────

class TestBuildSigningHeaders:
    def test_returns_three_headers_with_one_secret(self):
        payload = {"event": "chain.updated"}
        headers = build_signing_headers(payload, ["secret-a"])
        assert "X-Aegis-Timestamp" in headers
        assert "X-Aegis-Signature" in headers
        assert headers["X-Aegis-Signature-Version"] == "1"

    def test_multi_secret_produces_comma_separated_sigs(self):
        payload = {"event": "test"}
        headers = build_signing_headers(payload, ["sec-a", "sec-b"])
        sigs = headers["X-Aegis-Signature"].split(",")
        assert len(sigs) == 2
        for s in sigs:
            assert s.startswith("v1=")

    def test_empty_secrets_returns_empty_dict(self):
        assert build_signing_headers({"x": 1}, []) == {}

    def test_all_sigs_share_same_timestamp(self):
        payload = {"event": "test"}
        headers = build_signing_headers(payload, ["sec-a", "sec-b", "sec-c"])
        ts_str = headers["X-Aegis-Timestamp"]
        # All signatures should verify against their respective secrets
        for secret in ["sec-a", "sec-b", "sec-c"]:
            matched = any(
                verify_signature(payload, secret, ts_str, sig)
                for sig in headers["X-Aegis-Signature"].split(",")
            )
            assert matched, f"no matching sig for secret starting {secret[:5]}"

    def test_multi_secret_receiver_can_verify_with_either(self):
        """Receiver with old key can still verify during rotation."""
        payload = {"event": "finding.created", "sev": "critical"}
        old_secret = "old-rotation-key"
        new_secret = "new-rotation-key"
        headers = build_signing_headers(payload, [old_secret, new_secret])
        ts_str = headers["X-Aegis-Timestamp"]
        all_sigs = headers["X-Aegis-Signature"].split(",")

        for secret in [old_secret, new_secret]:
            assert any(verify_signature(payload, secret, ts_str, sig) for sig in all_sigs)


# ── Helpers ───────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_generate_secret_length(self):
        raw = _generate_secret()
        # token_urlsafe(32) encodes 32 bytes → ~43 chars base64url
        assert len(raw) >= 40

    def test_generate_secret_uniqueness(self):
        secrets = {_generate_secret() for _ in range(50)}
        assert len(secrets) == 50

    def test_hash_secret_is_sha256_hex(self):
        raw = "test-secret"
        result = _hash_secret(raw)
        expected = hashlib.sha256(raw.encode()).hexdigest()
        assert result == expected
        assert len(result) == 64


# ── DB integration tests ──────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def _dest_id():
    """Create a webhook destination and return its integer ID."""
    from src.notifications.destination import create_destination
    dest = create_destination(
        org_id="example-org",
        destination_type="webhook",
        name="hmac-test-webhook",
        config={"url": "https://example.org/webhook"},
    )
    return dest["id"]


class TestSigningSecretDB:
    def test_create_first_secret(self, _dest_id):
        from src.notifications.webhook_signing import create_signing_secret, list_signing_secrets
        meta, raw = create_signing_secret(_dest_id)
        assert meta["version"] == 1
        assert meta["status"] == "active"
        assert len(raw) >= 40
        # raw is not stored in metadata
        assert "raw" not in meta

    def test_list_returns_metadata_without_raw(self, _dest_id):
        from src.notifications.webhook_signing import list_signing_secrets
        rows = list_signing_secrets(_dest_id)
        for row in rows:
            assert "raw" not in row
            assert "secret_hash" not in row

    def test_rotation_demotes_active_to_rotating(self, _dest_id):
        from src.notifications.webhook_signing import create_signing_secret, list_signing_secrets
        # Create a second secret
        meta2, _ = create_signing_secret(_dest_id)
        assert meta2["version"] == 2
        assert meta2["status"] == "active"

        rows = list_signing_secrets(_dest_id)
        statuses = {r["version"]: r["status"] for r in rows}
        assert statuses[2] == "active"
        assert statuses[1] == "rotating"

    def test_revoke_specific_version(self, _dest_id):
        from src.notifications.webhook_signing import revoke_signing_secret_version, list_signing_secrets
        result = revoke_signing_secret_version(_dest_id, 1)
        assert result is not None
        assert result["status"] == "revoked"
        assert result["revoked_at"] is not None

        rows = list_signing_secrets(_dest_id)
        v1 = next(r for r in rows if r["version"] == 1)
        assert v1["status"] == "revoked"

    def test_revoke_nonexistent_version_returns_none(self, _dest_id):
        from src.notifications.webhook_signing import revoke_signing_secret_version
        result = revoke_signing_secret_version(_dest_id, 999)
        assert result is None

    def test_persist_and_retrieve_raw_secrets(self, _dest_id):
        from src.notifications.webhook_signing import (
            create_signing_secret,
            persist_raw_secret_to_channel,
            get_raw_secrets_for_channel,
        )
        meta, raw = create_signing_secret(_dest_id)
        persist_raw_secret_to_channel(_dest_id, meta["version"], raw)

        retrieved = get_raw_secrets_for_channel(_dest_id)
        assert raw in retrieved

    def test_revoke_removes_raw_from_active_list(self):
        """Uses a dedicated dest so state from other tests doesn't interfere."""
        from src.notifications.destination import create_destination
        from src.notifications.webhook_signing import (
            create_signing_secret,
            persist_raw_secret_to_channel,
            revoke_raw_secret_in_channel,
            get_raw_secrets_for_channel,
        )
        dest = create_destination(
            org_id="example-org",
            destination_type="webhook",
            name="revoke-test-wh",
            config={"url": "https://example.org/hook"},
        )
        channel_id = dest["id"]

        meta, raw = create_signing_secret(channel_id)
        persist_raw_secret_to_channel(channel_id, meta["version"], raw)

        before = get_raw_secrets_for_channel(channel_id)
        assert raw in before

        revoke_raw_secret_in_channel(channel_id, meta["version"])
        after = get_raw_secrets_for_channel(channel_id)
        assert raw not in after

    def test_full_roundtrip_sign_and_verify(self, _dest_id):
        """End-to-end: generate secret, sign payload, verify headers."""
        from src.notifications.webhook_signing import (
            create_signing_secret,
            persist_raw_secret_to_channel,
            get_raw_secrets_for_channel,
            build_signing_headers,
            verify_signature,
        )
        meta, raw = create_signing_secret(_dest_id)
        persist_raw_secret_to_channel(_dest_id, meta["version"], raw)

        payload = {"event_type": "finding.created", "severity": "critical"}
        raw_secrets = get_raw_secrets_for_channel(_dest_id)
        headers = build_signing_headers(payload, raw_secrets)

        assert "X-Aegis-Signature" in headers
        ts_str = headers["X-Aegis-Timestamp"]
        all_sigs = headers["X-Aegis-Signature"].split(",")

        assert any(verify_signature(payload, raw, ts_str, sig) for sig in all_sigs)
