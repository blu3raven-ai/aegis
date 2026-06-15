from __future__ import annotations

import hashlib
import hmac

from src.connectors.webhooks.signature import (
    verify_hmac_sha256,
    verify_token_eq,
)


def _hmac_header(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_hmac_sha256_accepts_valid_signature():
    body = b'{"action":"opened"}'
    secret = "shared"
    header = _hmac_header(secret, body)
    assert verify_hmac_sha256(body, header, secret) is True


def test_hmac_sha256_rejects_wrong_secret():
    body = b"payload"
    header = _hmac_header("right", body)
    assert verify_hmac_sha256(body, header, "wrong") is False


def test_hmac_sha256_rejects_missing_sha_prefix():
    body = b"payload"
    digest = hmac.new(b"k", body, hashlib.sha256).hexdigest()
    # Missing "sha256=" prefix
    assert verify_hmac_sha256(body, digest, "k") is False


def test_hmac_sha256_rejects_empty_header():
    assert verify_hmac_sha256(b"x", "", "secret") is False


def test_hmac_sha256_rejects_empty_secret():
    """An unconfigured secret fails closed — never let an empty key pass."""
    body = b"payload"
    header = _hmac_header("any", body)
    assert verify_hmac_sha256(body, header, "") is False


def test_hmac_sha256_handles_large_body():
    body = b"x" * (1 << 20)  # 1 MiB
    secret = "k"
    header = _hmac_header(secret, body)
    assert verify_hmac_sha256(body, header, secret) is True


def test_token_eq_matches_identical():
    assert verify_token_eq("token-abc", "token-abc") is True


def test_token_eq_rejects_mismatched():
    assert verify_token_eq("token-abc", "token-xyz") is False


def test_token_eq_rejects_empty_secret():
    assert verify_token_eq("", "anything") is False


def test_token_eq_rejects_empty_header():
    assert verify_token_eq("secret", "") is False
