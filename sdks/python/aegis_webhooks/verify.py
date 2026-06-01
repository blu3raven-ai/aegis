"""HMAC-SHA256 signature verification for Aegis webhook deliveries.

Mirrors the signing logic in backend/src/notifications/webhook_signing.py so
receivers can validate authenticity and replay protection without rolling their
own crypto.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Mapping


class AegisWebhookError(Exception):
    """Base class for all Aegis webhook verification errors."""


class InvalidTimestampError(AegisWebhookError):
    """Timestamp is missing, unparseable, or outside the tolerance window."""


class InvalidSignatureError(AegisWebhookError):
    """No candidate signature matched any of the provided secrets."""


def _canonical_json(payload: Mapping | bytes | str) -> str:
    """Return the canonical JSON string used in the signed string.

    WHY: Phase 44 signs `{ts}.{canonical_json}` where canonical means
    sort_keys=True and no whitespace — matches json.dumps defaults in
    webhook_signing.py::sign_payload exactly.
    """
    if isinstance(payload, (bytes, str)):
        # Re-parse so we sort keys regardless of original serialisation order
        obj = json.loads(payload)
    else:
        obj = payload
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def _case_insensitive(headers: Mapping[str, str]) -> dict[str, str]:
    """Return a lowercase-keyed copy of headers.

    WHY: RFC 7230 §3.2 declares HTTP header names case-insensitive; frameworks
    differ (Flask lowercases, Django keeps original case, etc.).
    """
    return {k.lower(): v for k, v in headers.items()}


def verify_signature(
    payload: Mapping | bytes | str,
    secret: str | list[str],
    headers: Mapping[str, str],
    *,
    tolerance_seconds: int = 300,
    current_time: int | None = None,
) -> None:
    """Verify an Aegis webhook signature.

    Raises ``InvalidTimestampError`` or ``InvalidSignatureError`` on failure.
    Returns ``None`` on success (never returns True/False — callers should
    treat any return as success and only catch exceptions on failure).

    Parameters
    ----------
    payload:
        The raw request body as ``bytes`` / ``str``, or the already-parsed
        JSON object as a ``dict``.  If bytes/str the function re-parses it
        to produce canonical JSON.
    secret:
        A single signing secret string, or a list of secrets (pass
        ``[old, new]`` during a rotation window — verification passes if
        any secret matches).
    headers:
        The HTTP request headers.  Lookup is case-insensitive so both
        ``X-Aegis-Signature`` and ``x-aegis-signature`` are accepted.
    tolerance_seconds:
        Maximum age of a delivery in seconds.  Deliveries older or
        future-dated beyond this window are rejected to prevent replay
        attacks.  Default: 300 (5 minutes), matching the server default.
    current_time:
        Override the current Unix timestamp used for the tolerance check.
        Intended for unit testing only.
    """
    ci = _case_insensitive(headers)

    # ── Extract required headers ────────────────────────────────────────────
    timestamp_str = ci.get("x-aegis-timestamp")
    signature_header = ci.get("x-aegis-signature")

    if timestamp_str is None or signature_header is None:
        raise AegisWebhookError(
            "Missing required headers: X-Aegis-Timestamp and X-Aegis-Signature must be present"
        )

    # ── Validate timestamp ──────────────────────────────────────────────────
    try:
        ts = int(timestamp_str)
    except (ValueError, TypeError) as exc:
        raise InvalidTimestampError(
            f"X-Aegis-Timestamp is not a valid integer: {timestamp_str!r}"
        ) from exc

    now = current_time if current_time is not None else int(time.time())
    age = now - ts
    if abs(age) > tolerance_seconds:
        raise InvalidTimestampError(
            f"Timestamp is outside the tolerance window "
            f"(age={age}s, tolerance={tolerance_seconds}s)"
        )

    # ── Build signed string ─────────────────────────────────────────────────
    canonical = _canonical_json(payload)
    signed = f"{timestamp_str}.{canonical}".encode()

    # ── Collect candidate (v1=<hex>) values from the header ─────────────────
    # WHY: Rotation sends multiple comma-separated signatures; we accept any.
    candidates = [s.strip() for s in signature_header.split(",") if s.strip()]

    # ── Verify against each secret × each candidate signature ───────────────
    secrets_list = [secret] if isinstance(secret, str) else secret
    for raw_secret in secrets_list:
        expected_hex = hmac.new(
            raw_secret.encode(), signed, hashlib.sha256
        ).hexdigest()
        expected = f"v1={expected_hex}"
        for candidate in candidates:
            # WHY: hmac.compare_digest prevents timing-based secret leakage.
            if hmac.compare_digest(expected, candidate):
                return  # Success — at least one pair matches

    raise InvalidSignatureError(
        "No candidate signature matched any of the provided secrets"
    )
