import base64
import hashlib
import hmac
import json
import time
import os

import pytest

from src.auth.jwt import verify_internal_jwt


# ---------------------------------------------------------------------------
# Helper: build a valid JWT using the same algorithm as the production code
# ---------------------------------------------------------------------------

def _b64url(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _make_jwt(
    sub: str = "user-1",
    role: str = "admin",
    secret: str = "a" * 64,
    exp_offset: int = 30,
    alg: str = "HS256",
) -> str:
    header = _b64url(json.dumps({"alg": alg, "typ": "JWT"}))
    now = int(time.time())
    payload = _b64url(json.dumps({"sub": sub, "role": role, "iat": now, "exp": now + exp_offset}))
    
    if len(secret) == 64:
        try:
            key = bytes.fromhex(secret)
        except ValueError:
            key = secret.encode()
    else:
        key = secret.encode()
        
    sig = _b64url(hmac.new(key, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_valid_token_accepted(monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    claims = verify_internal_jwt(_make_jwt(sub="user-1", role="admin", secret=secret))
    assert claims["sub"] == "user-1"
    assert claims["role"] == "admin"


def test_expired_token_rejected(monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    # Expired 10 seconds ago, beyond 5s skew tolerance
    token = _make_jwt(secret=secret, exp_offset=-10)
    with pytest.raises(ValueError, match="token expired"):
        verify_internal_jwt(token)


def test_skew_tolerance_accepted(monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    # Expired 2 seconds ago, within 5s skew tolerance
    token = _make_jwt(secret=secret, exp_offset=-2)
    claims = verify_internal_jwt(token)
    assert claims["sub"] == "user-1"


def test_tampered_signature_rejected(monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    parts = _make_jwt(secret=secret).split(".")
    parts[2] = parts[2][:-4] + "xxxx"  # corrupt last 4 chars of signature
    with pytest.raises(ValueError, match="invalid signature"):
        verify_internal_jwt(".".join(parts))


def test_wrong_algorithm_rejected(monkeypatch):
    secret = "a" * 64
    monkeypatch.setenv("JWT_SHARED_SECRET", secret)
    token = _make_jwt(secret=secret, alg="RS256")
    with pytest.raises(ValueError, match="unsupported algorithm"):
        verify_internal_jwt(token)


def test_malformed_token_rejected(monkeypatch):
    monkeypatch.setenv("JWT_SHARED_SECRET", "a" * 64)
    with pytest.raises(ValueError, match="malformed token"):
        verify_internal_jwt("only.two")


def test_missing_secret_raises(monkeypatch):
    monkeypatch.setenv("FASTAPI_ENV", "production")
    monkeypatch.delenv("JWT_SHARED_SECRET", raising=False)
    with pytest.raises(ValueError, match="JWT_SHARED_SECRET not set"):
        verify_internal_jwt(_make_jwt())
