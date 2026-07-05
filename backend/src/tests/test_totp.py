"""Contract tests for the shared TOTP (RFC 6238) verifier.

The code generator is validated against the canonical RFC 4226 HOTP test
vectors (TOTP at counter C == HOTP at counter C), and verify_totp's acceptance
window / empty-secret / encrypted-secret behaviour is locked with a fixed clock.
"""
from __future__ import annotations

import base64

import pytest

from src.shared import totp as totp_mod
from src.shared.totp import _totp_code_at, verify_totp

# RFC 4226 Appendix D test key ("12345678901234567890") and its first ten
# 6-digit HOTP values.
_SECRET = base64.b32encode(b"12345678901234567890").decode()
_RFC_VECTORS = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
]


class _Clock:
    def __init__(self, t: float):
        self.t = t

    def time(self) -> float:
        return self.t


@pytest.fixture
def fixed_clock(monkeypatch):
    # Realistic epoch -> a large positive counter (avoids the counter<0 edge).
    c = _Clock(1_700_000_000.0)
    monkeypatch.setattr(totp_mod, "time", c)
    return c


def _counter(clock: _Clock) -> int:
    return int(clock.t) // 30


def test_code_matches_rfc4226_vectors():
    for counter, expected in enumerate(_RFC_VECTORS):
        assert _totp_code_at(_SECRET, counter) == expected


def test_verify_accepts_current_code(fixed_clock):
    code = _totp_code_at(_SECRET, _counter(fixed_clock))
    assert verify_totp(_SECRET, code) is True


def test_verify_window_accepts_plus_minus_one(fixed_clock):
    c = _counter(fixed_clock)
    assert verify_totp(_SECRET, _totp_code_at(_SECRET, c - 1)) is True
    assert verify_totp(_SECRET, _totp_code_at(_SECRET, c + 1)) is True


def test_verify_rejects_outside_window(fixed_clock):
    c = _counter(fixed_clock)
    assert verify_totp(_SECRET, _totp_code_at(_SECRET, c + 2)) is False
    # A widened window admits the same step.
    assert verify_totp(_SECRET, _totp_code_at(_SECRET, c + 2), window=2) is True


def test_verify_rejects_wrong_code(fixed_clock):
    current = _totp_code_at(_SECRET, _counter(fixed_clock))
    bogus = "000000" if current != "000000" else "111111"
    assert verify_totp(_SECRET, bogus) is False


def test_empty_secret_is_false(fixed_clock):
    assert verify_totp("", _RFC_VECTORS[0]) is False


def test_encrypted_secret_is_decrypted(monkeypatch, fixed_clock):
    monkeypatch.setattr(totp_mod, "is_encrypted", lambda s: True)
    monkeypatch.setattr(totp_mod, "decrypt_string", lambda s, *, strict=False: _SECRET)
    code = _totp_code_at(_SECRET, _counter(fixed_clock))
    assert verify_totp("enc:ciphertext-placeholder", code) is True
