"""Shared Fernet encryption utilities for application-level field encryption.

Derives a deterministic Fernet key from RUNNER_ENCRYPTION_KEY. Used to encrypt
sensitive fields (source connection auth, TOTP secrets) at rest in the database.

Backward compatibility: callers should check for the "gAAAAA" (Fernet) prefix
before decrypting — unencrypted legacy data is returned as-is.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
from typing import Any

_logger = logging.getLogger(__name__)

# Lazy-initialised cipher (created on first call)
_cipher = None


def _get_cipher():
    """Derive a Fernet key from RUNNER_ENCRYPTION_KEY.

    Backwards-compat: JWT_SHARED_SECRET is accepted for one transitional
    release. Remove the fallback in the next maintenance window.
    """
    global _cipher
    if _cipher is not None:
        return _cipher

    from cryptography.fernet import Fernet

    secret = os.environ.get("RUNNER_ENCRYPTION_KEY") or os.environ.get("JWT_SHARED_SECRET", "")
    if not secret:
        if os.environ.get("FASTAPI_ENV") != "production":
            secret = secrets.token_hex(32)
            _logger.warning(
                "[security] RUNNER_ENCRYPTION_KEY not set — using ephemeral key for field encryption"
            )
        else:
            raise RuntimeError("RUNNER_ENCRYPTION_KEY not set — cannot encrypt sensitive fields")

    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    _cipher = Fernet(key)
    return _cipher


def encrypt_string(plaintext: str) -> str:
    """Encrypt a plaintext string, returning the Fernet token as a UTF-8 string."""
    if not plaintext:
        return plaintext
    cipher = _get_cipher()
    return cipher.encrypt(plaintext.encode()).decode()


def decrypt_string(ciphertext: str) -> str:
    """Decrypt a Fernet-encrypted string. Returns the original plaintext.

    If decryption fails (corrupted data, key rotation), returns empty string
    rather than leaking or crashing.
    """
    if not ciphertext:
        return ciphertext
    cipher = _get_cipher()
    try:
        return cipher.decrypt(ciphertext.encode()).decode()
    except Exception:
        _logger.warning("[security] Fernet decryption failed — returning empty string")
        return ""


def is_encrypted(value: str) -> bool:
    """Check whether a string looks like a Fernet token (starts with 'gAAAAA')."""
    return isinstance(value, str) and value.startswith("gAAAAA")


def encrypt_dict(data: dict[str, Any]) -> str:
    """Encrypt an entire dict as a JSON blob, returning a Fernet token string."""
    if not data:
        return ""
    plaintext = json.dumps(data, separators=(",", ":"), sort_keys=True)
    return encrypt_string(plaintext)


def decrypt_dict(ciphertext: str) -> dict[str, Any]:
    """Decrypt a Fernet-encrypted JSON dict. Returns {} on failure."""
    if not ciphertext:
        return {}
    plaintext = decrypt_string(ciphertext)
    if not plaintext:
        return {}
    try:
        return json.loads(plaintext)
    except (json.JSONDecodeError, TypeError):
        _logger.warning("[security] Decrypted auth blob is not valid JSON")
        return {}
