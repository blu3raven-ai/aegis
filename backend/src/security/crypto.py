"""Symmetric encryption for sensitive config values stored in the database."""

from __future__ import annotations

import os

from cryptography.fernet import Fernet, InvalidToken


def _fernet() -> Fernet:
    key = os.environ.get("AEGIS_SECRET_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "AEGIS_SECRET_ENCRYPTION_KEY is not set — cannot encrypt or decrypt secrets"
        )
    return Fernet(key.encode())


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str | None) -> str | None:
    if ciphertext is None:
        return None
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise RuntimeError("Secret decryption failed (invalid token or wrong key)") from exc
