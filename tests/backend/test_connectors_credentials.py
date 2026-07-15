from __future__ import annotations

from src.connectors.credentials import (
    generate_signing_secret,
    hash_secret,
    verify_secret,
)


def test_generate_signing_secret_is_url_safe_and_long_enough():
    secret = generate_signing_secret()
    assert isinstance(secret, str)
    assert len(secret) >= 32
    # URL-safe alphabet — no padding or unsafe chars
    assert all(c.isalnum() or c in "-_" for c in secret)


def test_generated_secrets_are_unique():
    a = generate_signing_secret()
    b = generate_signing_secret()
    assert a != b


def test_hash_then_verify_roundtrip():
    secret = "my-shared-secret"
    digest = hash_secret(secret)
    assert verify_secret(secret, digest) is True


def test_verify_rejects_tampered_secret():
    digest = hash_secret("right")
    assert verify_secret("wrong", digest) is False


def test_hash_is_deterministic_for_same_input():
    a = hash_secret("same")
    b = hash_secret("same")
    assert a == b


def test_hash_output_is_hex():
    digest = hash_secret("foo")
    assert isinstance(digest, str)
    int(digest, 16)  # raises ValueError if not valid hex
    assert len(digest) == 64  # sha256 hex digest length
