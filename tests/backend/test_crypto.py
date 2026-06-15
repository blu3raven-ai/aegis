import os
import pytest


def test_fernet_roundtrip(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from src.security.crypto import encrypt, decrypt
    cipher = encrypt("hello world")
    assert cipher != "hello world"
    assert decrypt(cipher) == "hello world"


def test_decrypt_none_returns_none(monkeypatch):
    monkeypatch.setenv("AEGIS_SECRET_ENCRYPTION_KEY", "FAjK_lhsKHqBJ4uYY3oRWAa7c1pTkbHIfk7gjhFCpx8=")
    from src.security.crypto import decrypt
    assert decrypt(None) is None


def test_encrypt_raises_without_key(monkeypatch):
    monkeypatch.delenv("AEGIS_SECRET_ENCRYPTION_KEY", raising=False)
    from src.security.crypto import encrypt
    with pytest.raises(RuntimeError, match="AEGIS_SECRET_ENCRYPTION_KEY"):
        encrypt("anything")
