"""Verification-layer coverage for the OIDC id_token exchange.

The security-critical contract is that `exchange_code` binds the id_token to
this RP: a token whose `aud` is a different client, or whose `iss` differs from
the discovery issuer, must be rejected even though it is validly signed by the
IdP's key. The signing key, token endpoint, and JWKS fetch are mocked; the JWT
itself is a genuinely RS256-signed token so authlib's real verification runs.
"""
from __future__ import annotations

import os
import socket
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)

import pytest
from authlib.jose import JsonWebKey, JsonWebToken

from src.auth.federation import oidc as oidc_mod
from src.auth.federation.oidc import exchange_code


@pytest.fixture(autouse=True)
def _resolve_test_hosts(monkeypatch):
    # exchange_code's SSRF guard resolves the discovery/JWKS hosts. Only
    # synthesize a public IP for hosts that don't really resolve (the example
    # endpoints); real hosts keep resolving normally. Blocking behavior is
    # covered in test_settings_url_guard.
    real = socket.getaddrinfo

    def _stub(host, *args, **kwargs):
        try:
            return real(host, *args, **kwargs)
        except socket.gaierror:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr("socket.getaddrinfo", _stub)

_ISSUER = "https://idp.example"
_CLIENT_ID = "client-a"
_NONCE = "nonce-xyz"
_KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True)
_JWKS = {"keys": [_KEY.as_dict(is_private=False)]}


def _sign(*, aud: str, iss: str, nonce: str = _NONCE, email_verified=True, alg: str = "RS256") -> str:
    now = int(time.time())
    payload = {
        "sub": "subject-1",
        "iss": iss,
        "aud": aud,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "email": "user@acme.test",
        "email_verified": email_verified,
    }
    header = {"alg": alg, "kid": _KEY.as_dict().get("kid")}
    return JsonWebToken([alg]).encode(header, payload, _KEY).decode("ascii")


def _row() -> SimpleNamespace:
    return SimpleNamespace(
        oidc_discovery_url="https://idp.example/.well-known/openid-configuration",
        oidc_client_id=_CLIENT_ID,
    )


@asynccontextmanager
async def _fake_httpx_client(*_a, **_k):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value=_JWKS)
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    yield client


def _run_exchange(id_token: str):
    disc = {
        "issuer": _ISSUER,
        "token_endpoint": f"{_ISSUER}/token",
        "jwks_uri": f"{_ISSUER}/jwks",
        "authorization_endpoint": f"{_ISSUER}/authorize",
    }
    fake_oauth = MagicMock()
    fake_oauth.fetch_token = AsyncMock(return_value={"id_token": id_token})
    import asyncio

    with patch.object(oidc_mod, "_discovery", AsyncMock(return_value=disc)), \
            patch.object(oidc_mod, "_client_secret", return_value="secret"), \
            patch.object(oidc_mod, "AsyncOAuth2Client", return_value=fake_oauth), \
            patch.object(oidc_mod.httpx, "AsyncClient", _fake_httpx_client):
        return asyncio.run(exchange_code(_row(), "https://sp.example/cb", "code", _NONCE))


def test_correct_aud_and_iss_succeeds():
    identity = _run_exchange(_sign(aud=_CLIENT_ID, iss=_ISSUER))
    assert identity.subject == "subject-1"
    assert identity.email == "user@acme.test"
    assert identity.email_verified is True


def test_wrong_audience_is_rejected():
    # Token minted for a different client at the same issuer must not be accepted.
    with pytest.raises(Exception):
        _run_exchange(_sign(aud="client-b", iss=_ISSUER))


def test_wrong_issuer_is_rejected():
    with pytest.raises(Exception):
        _run_exchange(_sign(aud=_CLIENT_ID, iss="https://evil.example"))


def test_email_verified_absent_yields_unverified_identity():
    identity = _run_exchange(_sign(aud=_CLIENT_ID, iss=_ISSUER, email_verified=None))
    assert identity.email_verified is False


def test_email_verified_string_true_is_honored():
    identity = _run_exchange(_sign(aud=_CLIENT_ID, iss=_ISSUER, email_verified="true"))
    assert identity.email_verified is True
