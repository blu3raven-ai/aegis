"""TOTP (RFC 6238) verification — shared helper.

Single source of truth for 6-digit TOTP with SHA-1, 30-second period, and
window=1. Both ``internal_router`` and ``login_router`` import from here to
avoid drift.
"""
from __future__ import annotations

import base64
import hmac
import struct
import time

from src.shared.encryption import decrypt_string, is_encrypted


def _totp_code_at(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32, casefold=True)
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, "sha1").digest()
    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % 10**6).zfill(6)


def verify_totp(secret: str, code: str, *, window: int = 1) -> bool:
    """Verify a 6-digit TOTP code against a base32 secret (RFC 6238).

    Decrypts the secret if it is stored encrypted. Returns False for empty or
    invalid input. ``window`` controls how many 30-second steps before/after
    the current counter are accepted (default 1).
    """
    if is_encrypted(secret):
        secret = decrypt_string(secret)
    if not secret:
        return False
    now_counter = int(time.time()) // 30
    return any(
        hmac.compare_digest(code, _totp_code_at(secret, now_counter + offset))
        for offset in range(-window, window + 1)
    )
