"""Symmetric encryption for sensitive job env vars.

Shared by jobs.py, FileBackedQueue, and RedisBackedQueue. Uses Fernet
over a PBKDF2-HMAC-SHA256 key derived from JWT_SHARED_SECRET, with
salt 'runner-job-env-vars' and 100 000 iterations. Encrypted values
are prefixed with 'ENC:' so they are wire-compatible across all queue
backends.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets

from cryptography.fernet import Fernet

_logger = logging.getLogger(__name__)

SENSITIVE_KEYS: frozenset[str] = frozenset({"GIT_TOKEN", "REGISTRY_TOKEN", "REGISTRY_AUTHS"})
_ENC_PREFIX = "ENC:"


def _get_cipher() -> Fernet:
    """Derive a Fernet key from JWT_SHARED_SECRET.

    Falls back to an ephemeral key in non-production environments so
    local dev and tests work without setting the env var. Raises in
    production to prevent silent data exposure.
    """
    secret = os.environ.get("JWT_SHARED_SECRET", "")
    if not secret:
        if os.environ.get("FASTAPI_ENV") != "production":
            secret = secrets.token_hex(32)
            _logger.warning(
                "[security] JWT_SHARED_SECRET not set — using ephemeral key for job encryption"
            )
        else:
            raise RuntimeError("JWT_SHARED_SECRET not set — cannot encrypt job env vars")
    key = base64.urlsafe_b64encode(
        hashlib.pbkdf2_hmac("sha256", secret.encode(), b"runner-job-env-vars", 100_000)
    )
    return Fernet(key)


def encrypt_env_vars(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of *env* with sensitive values encrypted."""
    cipher = _get_cipher()
    result: dict[str, str] = {}
    for k, v in env.items():
        if k in SENSITIVE_KEYS and v:
            result[k] = _ENC_PREFIX + cipher.encrypt(v.encode()).decode()
        else:
            result[k] = v
    return result


def decrypt_env_vars(env: dict[str, str]) -> dict[str, str]:
    """Return a copy of *env* with ENC:-prefixed values decrypted."""
    cipher = _get_cipher()
    result: dict[str, str] = {}
    for k, v in env.items():
        if isinstance(v, str) and v.startswith(_ENC_PREFIX):
            try:
                result[k] = cipher.decrypt(v[len(_ENC_PREFIX):].encode()).decode()
            except Exception:
                result[k] = ""  # Decryption failed — empty rather than leak
        else:
            result[k] = v
    return result
