"""Password hashing and verification — scrypt-based.

Single source of truth for the password format ``scrypt:v1:<salt-hex>:<hash-hex>``.
Both ``internal_router`` (BFF system endpoint) and ``login_router`` (cookie-based)
import from here to avoid drift.
"""
from __future__ import annotations

import hashlib
import hmac
import os

_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64


def hash_password(password: str) -> str:
    """Return ``scrypt:v1:<salt-hex>:<derived-hex>``."""
    salt = os.urandom(16)
    derived = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return f"scrypt:v1:{salt.hex()}:{derived.hex()}"


def verify_password(password: str, hash_str: str | None) -> bool:
    """Constant-time verify; returns False for None, malformed, or legacy plaintext input."""
    if not hash_str:
        return False
    if hash_str.startswith("scrypt:v1:"):
        parts = hash_str.split(":")
        if len(parts) != 4:
            return False
        try:
            salt = bytes.fromhex(parts[2])
            expected = bytes.fromhex(parts[3])
        except ValueError:
            return False
        derived = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
        )
        return hmac.compare_digest(derived, expected)
    # Legacy plaintext — constant-time compare
    return hmac.compare_digest(password.encode(), hash_str.encode())
