"""Symmetric encryption for sensitive config values stored in the database.

The Fernet key is derived from the single APP_SECRET root (via the shared
HKDF-per-context helper) rather than a separate raw key, so all at-rest secrets
trace back to one root. Decryption failures are raised loudly — a wrong/rotated
key must never silently yield an empty or garbage secret.
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from src.shared.encryption import derive_key

_CONTEXT = "settings_secret"


def _fernet() -> Fernet:
    return Fernet(derive_key(_CONTEXT))


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Secret decryption failed (invalid token or wrong key)") from exc
