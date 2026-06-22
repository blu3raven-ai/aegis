from __future__ import annotations

import base64
import hashlib
import hmac

from src.connectors.webhooks.signature import (
    verify_basic_auth,
    verify_bearer_token,
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


def _basic(secret: str) -> str:
    return "Basic " + base64.b64encode(secret.encode()).decode()


def test_basic_auth_accepts_valid():
    assert verify_basic_auth("user:pw", _basic("user:pw")) is True


def test_basic_auth_rejects_wrong_secret():
    assert verify_basic_auth("user:pw", _basic("user:other")) is False


def test_basic_auth_rejects_missing_prefix():
    raw = base64.b64encode(b"user:pw").decode()
    assert verify_basic_auth("user:pw", raw) is False


def test_basic_auth_rejects_empty_header():
    assert verify_basic_auth("user:pw", "") is False


def test_basic_auth_rejects_empty_secret():
    assert verify_basic_auth("", _basic("anything:x")) is False


def test_basic_auth_rejects_malformed_base64():
    assert verify_basic_auth("user:pw", "Basic !!!not-base64!!!") is False


def test_basic_auth_rejects_blank_payload():
    assert verify_basic_auth("user:pw", "Basic ") is False


def test_bearer_token_accepts_valid():
    assert verify_bearer_token("token-abc", "Bearer token-abc") is True


def test_bearer_token_rejects_wrong_secret():
    assert verify_bearer_token("token-abc", "Bearer token-xyz") is False


def test_bearer_token_rejects_missing_prefix():
    assert verify_bearer_token("token-abc", "token-abc") is False


def test_bearer_token_rejects_lowercase_prefix():
    assert verify_bearer_token("token-abc", "bearer token-abc") is False


def test_bearer_token_rejects_empty_header():
    assert verify_bearer_token("token-abc", "") is False


def test_bearer_token_rejects_empty_secret():
    assert verify_bearer_token("", "Bearer anything") is False


def test_bearer_token_rejects_blank_payload():
    assert verify_bearer_token("token-abc", "Bearer ") is False
