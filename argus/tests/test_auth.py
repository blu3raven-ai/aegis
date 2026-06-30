"""Tests for argus.auth token verification + the service gate."""
from __future__ import annotations

import jwt
import pytest
from fastapi.testclient import TestClient

from argus import auth
from argus.auth import (
    AuthError,
    JwtTokenVerifier,
    StaticTokenVerifier,
    TokenClaims,
    default_verifier,
)
from argus.service import app

_SECRET = "unit-test-signing-secret-padding-0123456789"
_ISSUER = "https://idp.example-org.invalid"
_AUDIENCE = "argus"


# ---- StaticTokenVerifier (dev/test) ----

def test_static_rejects_empty_token():
    with pytest.raises(AuthError):
        StaticTokenVerifier().verify("")


def test_static_accepts_any_token_when_unconfigured():
    claims = StaticTokenVerifier().verify("anything")
    assert claims.org_id == "dev-org"


def test_static_enforces_configured_secret():
    verifier = StaticTokenVerifier(expected="s3cret")
    with pytest.raises(AuthError):
        verifier.verify("wrong")
    assert verifier.verify("s3cret").org_id == "dev-org"


# ---- JwtTokenVerifier (production) ----

def _jwt_verifier(monkeypatch, **overrides) -> JwtTokenVerifier:
    """A JWT verifier whose JWKS lookup returns our symmetric test key."""
    verifier = JwtTokenVerifier(
        issuer=_ISSUER, audience=_AUDIENCE, algorithms=("HS256",), **overrides
    )

    class _Key:
        key = _SECRET

    monkeypatch.setattr(verifier, "_client", lambda: type("C", (), {
        "get_signing_key_from_jwt": staticmethod(lambda _token: _Key()),
    })())
    return verifier


def _token(**claims) -> str:
    payload = {"iss": _ISSUER, "aud": _AUDIENCE, "exp": 9999999999, "org_id": "acme-org"}
    payload.update(claims)
    return jwt.encode(payload, _SECRET, algorithm="HS256")


def test_jwt_verifies_valid_token_and_reads_org(monkeypatch):
    claims = _jwt_verifier(monkeypatch).verify(_token(sub="runner-1", scope="match verify"))
    assert claims.org_id == "acme-org"
    assert claims.subject == "runner-1"
    assert claims.scopes == ["match", "verify"]
    assert claims.issuer == _ISSUER


def test_jwt_rejects_expired_token(monkeypatch):
    with pytest.raises(AuthError):
        _jwt_verifier(monkeypatch).verify(_token(exp=1))


def test_jwt_rejects_wrong_issuer(monkeypatch):
    with pytest.raises(AuthError):
        _jwt_verifier(monkeypatch).verify(_token(iss="https://evil.invalid"))


def test_jwt_rejects_wrong_audience(monkeypatch):
    with pytest.raises(AuthError):
        _jwt_verifier(monkeypatch).verify(_token(aud="someone-else"))


def test_jwt_rejects_missing_org_claim(monkeypatch):
    with pytest.raises(AuthError):
        _jwt_verifier(monkeypatch).verify(_token(org_id=None))


# ---- default_verifier selection ----

def test_default_verifier_is_static_without_issuer(monkeypatch):
    monkeypatch.delenv("ARGUS_OIDC_ISSUER", raising=False)
    assert isinstance(default_verifier(), StaticTokenVerifier)


def test_default_verifier_is_jwt_with_issuer(monkeypatch):
    monkeypatch.setenv("ARGUS_OIDC_ISSUER", _ISSUER)
    assert isinstance(default_verifier(), JwtTokenVerifier)


# ---- the service gate ----

@pytest.fixture
def _reset_auth():
    auth.reset_verifier()
    yield
    auth.reset_verifier()


def test_gate_rejects_wrong_token_when_secret_configured(monkeypatch, _reset_auth):
    monkeypatch.setenv("ARGUS_TOKEN", "the-secret")
    client = TestClient(app)
    body = {"surface": "deps", "components": []}

    bad = client.post("/v1/match", json=body, headers={"Authorization": "Bearer nope"})
    assert bad.status_code == 401

    good = client.post(
        "/v1/match", json=body, headers={"Authorization": "Bearer the-secret"}
    )
    assert good.status_code == 200


def test_require_bearer_returns_claims():
    claims = StaticTokenVerifier().verify("tok")
    assert isinstance(claims, TokenClaims)
