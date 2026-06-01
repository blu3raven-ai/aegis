"""Tests for aegis_webhooks.verify_signature.

Fixture approach: all tests build signatures using the same signing primitive
as Phase 44 (webhook_signing.sign_payload logic) so we test the full
sign→verify round-trip without depending on backend imports.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest

from aegis_webhooks import (
    AegisWebhookError,
    InvalidSignatureError,
    InvalidTimestampError,
    verify_signature,
)

# ── Helpers that mirror Phase 44's sign_payload ───────────────────────────────

FIXTURES = Path(__file__).parent / "fixtures"
TEST_SECRET = "test-secret-123"
ALT_SECRET = "alt-secret-456"


def _canonical(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _sign(payload: dict, secret: str, ts: int) -> str:
    signed = f"{ts}.{_canonical(payload)}".encode()
    hex_sig = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    return f"v1={hex_sig}"


def _headers(sig: str, ts: int, *, extra: dict | None = None) -> dict[str, str]:
    h = {
        "X-Aegis-Timestamp": str(ts),
        "X-Aegis-Signature": sig,
        "X-Aegis-Signature-Version": "1",
    }
    if extra:
        h.update(extra)
    return h


def _now() -> int:
    return int(time.time())


# ── Load sample payload ───────────────────────────────────────────────────────

with open(FIXTURES / "sample_payload.json") as fh:
    SAMPLE_PAYLOAD = json.load(fh)


# ── Happy path ────────────────────────────────────────────────────────────────

class TestHappyPath:
    def test_valid_dict_payload(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, ts))

    def test_valid_bytes_payload(self):
        ts = _now()
        payload_bytes = json.dumps(SAMPLE_PAYLOAD).encode()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        verify_signature(payload_bytes, TEST_SECRET, _headers(sig, ts))

    def test_valid_str_payload(self):
        ts = _now()
        payload_str = json.dumps(SAMPLE_PAYLOAD)
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        verify_signature(payload_str, TEST_SECRET, _headers(sig, ts))

    def test_returns_none_on_success(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        result = verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, ts))
        assert result is None


# ── Tampered payload ──────────────────────────────────────────────────────────

class TestTamperedPayload:
    def test_tampered_payload_raises_invalid_signature(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        tampered = {**SAMPLE_PAYLOAD, "event": "finding.deleted"}
        with pytest.raises(InvalidSignatureError):
            verify_signature(tampered, TEST_SECRET, _headers(sig, ts))

    def test_wrong_secret_raises_invalid_signature(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, "wrong-secret", ts)
        with pytest.raises(InvalidSignatureError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, ts))


# ── Timestamp validation ──────────────────────────────────────────────────────

class TestTimestamp:
    def test_expired_timestamp_raises_invalid_timestamp(self):
        old_ts = _now() - 400  # beyond 300s tolerance
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, old_ts)
        with pytest.raises(InvalidTimestampError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, old_ts))

    def test_future_timestamp_beyond_tolerance_raises(self):
        future_ts = _now() + 400
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, future_ts)
        with pytest.raises(InvalidTimestampError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, future_ts))

    def test_timestamp_at_boundary_is_accepted(self):
        # Exactly at the tolerance edge should pass
        ts = _now() - 299
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, ts))

    def test_non_integer_timestamp_raises(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        bad_headers = _headers(sig, ts)
        bad_headers["X-Aegis-Timestamp"] = "not-a-number"
        with pytest.raises(InvalidTimestampError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, bad_headers)

    def test_injectable_current_time(self):
        # WHY: current_time injection lets tests freeze time without monkeypatching
        ts = 1_700_000_000
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        # Verify succeeds when current_time == ts
        verify_signature(
            SAMPLE_PAYLOAD, TEST_SECRET, _headers(sig, ts), current_time=ts
        )
        # Verify fails when frozen time is outside window
        with pytest.raises(InvalidTimestampError):
            verify_signature(
                SAMPLE_PAYLOAD,
                TEST_SECRET,
                _headers(sig, ts),
                current_time=ts + 400,
            )


# ── Case-insensitive headers ──────────────────────────────────────────────────

class TestCaseInsensitiveHeaders:
    def test_lowercase_header_names_accepted(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        headers = {
            "x-aegis-timestamp": str(ts),
            "x-aegis-signature": sig,
            "x-aegis-signature-version": "1",
        }
        verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, headers)

    def test_mixed_case_header_names_accepted(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        headers = {
            "X-Aegis-Timestamp": str(ts),
            "x-aegis-signature": sig,
        }
        verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, headers)


# ── Multiple signatures (rotation) ───────────────────────────────────────────

class TestMultipleSignatures:
    def test_any_valid_sig_in_header_succeeds(self):
        """During rotation the header may contain two v1= values — either match."""
        ts = _now()
        sig1 = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        sig2 = _sign(SAMPLE_PAYLOAD, ALT_SECRET, ts)
        combined = f"{sig1},{sig2}"
        # Verify against only one secret — matches its signature in the header
        verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(combined, ts))

    def test_none_matching_raises(self):
        ts = _now()
        sig1 = _sign(SAMPLE_PAYLOAD, "bad1", ts)
        sig2 = _sign(SAMPLE_PAYLOAD, "bad2", ts)
        combined = f"{sig1},{sig2}"
        with pytest.raises(InvalidSignatureError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, _headers(combined, ts))


# ── Multiple secrets (rotation — pass a list) ─────────────────────────────────

class TestMultipleSecrets:
    def test_list_with_matching_secret_succeeds(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, ALT_SECRET, ts)
        # ALT_SECRET is in the list so it should match
        verify_signature(SAMPLE_PAYLOAD, [TEST_SECRET, ALT_SECRET], _headers(sig, ts))

    def test_list_with_no_matching_secret_raises(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, "unrelated-secret", ts)
        with pytest.raises(InvalidSignatureError):
            verify_signature(SAMPLE_PAYLOAD, [TEST_SECRET, ALT_SECRET], _headers(sig, ts))

    def test_rotation_both_secret_and_sig_list(self):
        """Both header and secret list have two values — any intersection matches."""
        ts = _now()
        sig_old = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        sig_new = _sign(SAMPLE_PAYLOAD, ALT_SECRET, ts)
        combined_header = f"{sig_old},{sig_new}"
        verify_signature(
            SAMPLE_PAYLOAD,
            [TEST_SECRET, ALT_SECRET],
            _headers(combined_header, ts),
        )


# ── Missing headers ───────────────────────────────────────────────────────────

class TestMissingHeaders:
    def test_missing_timestamp_header_raises(self):
        ts = _now()
        sig = _sign(SAMPLE_PAYLOAD, TEST_SECRET, ts)
        with pytest.raises(AegisWebhookError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, {"X-Aegis-Signature": sig})

    def test_missing_signature_header_raises(self):
        ts = _now()
        with pytest.raises(AegisWebhookError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, {"X-Aegis-Timestamp": str(ts)})

    def test_empty_headers_raises(self):
        with pytest.raises(AegisWebhookError):
            verify_signature(SAMPLE_PAYLOAD, TEST_SECRET, {})


# ── Integration smokes ────────────────────────────────────────────────────────

class TestFlaskIntegration:
    """Integration-style smoke showing how to use in a Flask view."""

    def _make_flask_request_stub(self, payload: dict, secret: str):
        """Return a minimal Flask-like request stub with .data and .headers."""

        class FakeRequest:
            data = json.dumps(payload).encode()
            headers = {}

            def __init__(self, ts, sig):
                self.headers = {
                    "X-Aegis-Timestamp": str(ts),
                    "X-Aegis-Signature": sig,
                }

        ts = _now()
        sig = _sign(payload, secret, ts)
        return FakeRequest(ts, sig)

    def test_flask_verify_pattern(self):
        """Mirrors the typical Flask webhook handler pattern."""
        request = self._make_flask_request_stub(SAMPLE_PAYLOAD, TEST_SECRET)

        # In a real Flask view: verify_signature(request.data, WEBHOOK_SECRET, request.headers)
        verify_signature(request.data, TEST_SECRET, request.headers)

    def test_flask_tampered_body_raises(self):
        request = self._make_flask_request_stub(SAMPLE_PAYLOAD, TEST_SECRET)
        tampered = json.dumps({**SAMPLE_PAYLOAD, "event": "injected"}).encode()
        with pytest.raises(InvalidSignatureError):
            verify_signature(tampered, TEST_SECRET, request.headers)


class TestFastAPIIntegration:
    """Integration-style smoke showing how to use in a FastAPI route."""

    def _make_signed_headers(self, payload: dict, secret: str) -> dict[str, str]:
        ts = _now()
        sig = _sign(payload, secret, ts)
        return {
            "X-Aegis-Timestamp": str(ts),
            "X-Aegis-Signature": sig,
        }

    def test_fastapi_verify_pattern(self):
        """Mirrors a FastAPI route that receives raw body bytes + Header params."""
        raw_body: bytes = json.dumps(SAMPLE_PAYLOAD).encode()
        headers = self._make_signed_headers(SAMPLE_PAYLOAD, TEST_SECRET)

        # In a real FastAPI route: verify_signature(raw_body, WEBHOOK_SECRET, headers)
        verify_signature(raw_body, TEST_SECRET, headers)
