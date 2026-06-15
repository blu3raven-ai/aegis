"""Credential primitives — generate, hash, verify shared secrets.

Replaces ad-hoc `secrets.token_urlsafe` + custom SHA256 sites scattered
across notifications/webhook_signing.py and runner/storage.py.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


def generate_signing_secret(nbytes: int = 32) -> str:
    """Return a URL-safe, cryptographically random secret string.

    Default 32 bytes ≈ 43 chars of url-safe base64 — far more entropy than
    needed for HMAC-SHA256 signing keys."""
    return secrets.token_urlsafe(nbytes)


def hash_secret(secret: str) -> str:
    """Return the hex SHA-256 digest of `secret`.

    Used to store a one-way hash of a signing secret so the raw value never
    sits in the database. Verification compares hashes with a constant-time
    primitive — never the digests themselves directly."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def verify_secret(secret: str, expected_hash: str) -> bool:
    """Constant-time check that `hash_secret(secret) == expected_hash`."""
    return hmac.compare_digest(hash_secret(secret), expected_hash)
