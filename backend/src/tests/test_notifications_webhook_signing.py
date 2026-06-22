"""Unit tests for the pure-function builder in notifications.webhook_signing.

These cover the header-shape contract that downstream HMAC verifiers depend on,
the rotation behaviour when multiple raw secrets are passed in, and the
revoked-only / empty-list paths that must produce no signing headers.
"""
from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from src.notifications.webhook_signing import (
    TOLERANCE_SECONDS,
    build_signing_headers,
    sign_payload,
    verify_signature,
)




def test_build_signing_headers_empty_list_returns_empty_dict():
    # No raw secrets means the destination is mid-rotation with only revoked
    # entries, or has never been signed. We must NOT emit any signing headers
    # otherwise the receiver would reject the message instead of falling back.
    out = build_signing_headers({"k": "v"}, [])
    assert out == {}


def test_build_signing_headers_single_secret_emits_three_headers():
    payload = {"hello": "world"}
    secret = "secret-one"

    headers = build_signing_headers(payload, [secret])

    assert set(headers.keys()) == {
        "X-Aegis-Timestamp",
        "X-Aegis-Signature",
        "X-Aegis-Signature-Version",
    }
    assert headers["X-Aegis-Signature-Version"] == "1"
    assert headers["X-Aegis-Timestamp"].isdigit()
    assert headers["X-Aegis-Signature"].startswith("v1=")


def test_build_signing_headers_signature_round_trips_through_verify():
    # Producing headers and immediately verifying with the same secret + payload
    # must succeed — guards against subtle changes to canonical-json encoding.
    payload = {"a": 1, "b": [2, 3], "c": {"nested": True}}
    secret = "rotating-secret"

    headers = build_signing_headers(payload, [secret])
    ts = headers["X-Aegis-Timestamp"]
    sig = headers["X-Aegis-Signature"]

    assert verify_signature(payload, secret, ts, sig) is True


def test_build_signing_headers_multiple_secrets_comma_joined_in_priority_order():
    # During rotation both the new (active) and old (rotating) secret produce
    # signatures so receivers can verify with either key. Order of the input
    # list must be preserved in the output to make the active key first.
    payload = {"k": "v"}
    secrets = ["new-active", "old-rotating"]

    headers = build_signing_headers(payload, secrets)
    sigs = headers["X-Aegis-Signature"].split(",")

    assert len(sigs) == 2
    for s in sigs:
        assert s.startswith("v1=")

    # Each comma-joined signature must verify against the matching secret.
    ts = headers["X-Aegis-Timestamp"]
    assert verify_signature(payload, secrets[0], ts, sigs[0]) is True
    assert verify_signature(payload, secrets[1], ts, sigs[1]) is True


def test_build_signing_headers_signature_matches_canonical_json_hmac():
    # Lock the exact signed-string format so a receiver implementing the spec
    # from scratch can verify against our headers.
    payload = {"z": 1, "a": 2}
    secret = "k"

    headers = build_signing_headers(payload, [secret])
    ts_str = headers["X-Aegis-Timestamp"]
    sig_header = headers["X-Aegis-Signature"]

    # Canonical: sort_keys, no whitespace
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signed = f"{ts_str}.{canonical}".encode()
    expected_hex = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()

    assert sig_header == f"v1={expected_hex}"


def test_build_signing_headers_payload_change_invalidates_signature():
    payload_a = {"k": "v"}
    payload_b = {"k": "w"}
    secret = "k"

    headers = build_signing_headers(payload_a, [secret])
    ts = headers["X-Aegis-Timestamp"]
    sig = headers["X-Aegis-Signature"]

    # Verifying B against A's signature must fail — the timestamp is fine but
    # the canonical-json body differs, so the HMAC won't match.
    assert verify_signature(payload_b, secret, ts, sig) is False




def test_sign_payload_returns_versioned_signature_and_ts_seconds():
    # Direct contract on the lower-level builder — needed by anyone implementing
    # a custom dispatcher that doesn't use build_signing_headers.
    from datetime import datetime, timezone

    ts = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    payload = {"x": 1}
    secret = "k"

    ts_str, sig = sign_payload(payload, secret, ts)

    assert ts_str == str(int(ts.timestamp()))
    assert sig.startswith("v1=")


def test_verify_signature_outside_tolerance_window_returns_false():
    # Stale timestamps must be rejected to prevent replay attacks. We pass an
    # explicit out-of-window timestamp so the test is deterministic.
    payload = {"k": "v"}
    secret = "k"
    # A timestamp from very far in the past.
    stale_ts = "0"
    # Build a signature using the stale ts so only the timestamp check rejects.
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    signed = f"{stale_ts}.{canonical}".encode()
    sig = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()

    assert verify_signature(payload, secret, stale_ts, sig) is False


def test_verify_signature_malformed_timestamp_returns_false():
    assert verify_signature({"k": "v"}, "secret", "not-a-number", "v1=deadbeef") is False
    assert verify_signature({"k": "v"}, "secret", "", "v1=deadbeef") is False


def test_tolerance_is_300_seconds():
    # Lock the spec: receivers tune their own tolerance against this value.
    assert TOLERANCE_SECONDS == 300
