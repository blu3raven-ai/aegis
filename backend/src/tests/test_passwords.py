"""Contract tests for scrypt password hashing/verification.

Security-critical and previously untested. Locks the encoded format, salt
uniqueness, the verify roundtrip, and the rejection paths (None, malformed,
non-hex, wrong password) plus the legacy-plaintext fallback.
"""
from __future__ import annotations

import re

from src.shared.passwords import hash_password, verify_password

_FORMAT = re.compile(r"^scrypt:v1:[0-9a-f]{32}:[0-9a-f]{128}$")


def test_hash_format_and_lengths():
    h = hash_password("hunter2")
    assert _FORMAT.match(h), h  # 16-byte salt (32 hex) + 64-byte hash (128 hex)


def test_salt_is_random_per_call():
    a = hash_password("same-password")
    b = hash_password("same-password")
    assert a != b  # distinct random salts
    # ...yet both verify the original password.
    assert verify_password("same-password", a)
    assert verify_password("same-password", b)


def test_roundtrip_and_wrong_password():
    h = hash_password("correct horse battery staple")
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong", h) is False


def test_unicode_password_roundtrips():
    h = hash_password("pä55wörd-🔐")
    assert verify_password("pä55wörd-🔐", h) is True
    assert verify_password("pa55word", h) is False


def test_none_and_empty_hash_are_false():
    assert verify_password("x", None) is False
    assert verify_password("x", "") is False


def test_malformed_scrypt_hash_is_false():
    # Missing field.
    assert verify_password("x", "scrypt:v1:deadbeef") is False
    # Extra field.
    assert verify_password("x", "scrypt:v1:dead:beef:extra") is False
    # Non-hex salt/hash.
    assert verify_password("x", "scrypt:v1:zz:zz") is False


def test_legacy_plaintext_fallback():
    # A stored value that isn't a scrypt envelope is compared as plaintext.
    assert verify_password("plain-secret", "plain-secret") is True
    assert verify_password("plain-secret", "different") is False
