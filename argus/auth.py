"""Bearer-token verification for the Argus service.

Argus sits behind an OAuth2 access token. The customer's Aegis backend performs
a refresh-token grant against its IdP (``token_endpoint``) and ships the
resulting short-lived access token to the runner, which presents it here as a
Bearer credential. This module verifies that token and resolves the tenant it is
scoped to — so a forged or expired token is rejected at the door, and a valid
one can only ever reach its own org's data.

``org_id`` from the verified claims is the tenant boundary: handlers must scope
on ``TokenClaims.org_id`` (BOLA prevention), never on an org taken from the
request body.

Two verifiers ship:

* ``StaticTokenVerifier`` — dev/test only. Accepts a shared secret (``ARGUS_TOKEN``);
  with none configured it accepts any non-empty token and reports a dev org. It
  performs no cryptographic check and must never be the production verifier.
* ``JwtTokenVerifier`` — production. Verifies a signed JWT against the IdP's JWKS,
  enforcing signature, expiry, issuer and (when configured) audience, and reads
  the tenant from the org claim.

``default_verifier`` is the single swap point: it returns the JWT verifier when
an OIDC issuer is configured (``ARGUS_OIDC_ISSUER``), else the static dev one.
``get_verifier`` caches it process-wide so the JWKS keys are fetched once.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DEV_ORG = "dev-org"
# Claim names an IdP may carry the tenant under, in priority order.
_ORG_CLAIMS = ("org_id", "org", "tenant", "tenant_id")


class AuthError(Exception):
    """Raised when a bearer token cannot be verified."""


class TokenClaims(BaseModel):
    """The verified identity of a caller. ``org_id`` is the tenant boundary."""

    org_id: str
    subject: str | None = None
    scopes: list[str] = Field(default_factory=list)
    expires_at: int | None = None
    issuer: str | None = None


@runtime_checkable
class TokenVerifier(Protocol):
    """Verify a bearer token and return its claims, or raise ``AuthError``."""

    def verify(self, token: str) -> TokenClaims:
        ...


def _as_scopes(raw: Any) -> list[str]:
    """Normalise an OAuth ``scope`` claim (space-delimited string or list)."""
    if isinstance(raw, str):
        return raw.split()
    if isinstance(raw, (list, tuple)):
        return [str(s) for s in raw]
    return []


def _first_org_claim(claims: dict[str, Any]) -> str | None:
    for name in _ORG_CLAIMS:
        value = claims.get(name)
        if value:
            return str(value)
    return None


class StaticTokenVerifier:
    """Dev/test verifier. Performs no cryptographic check — not for production."""

    def __init__(self, expected: str | None = None, org_id: str = _DEV_ORG) -> None:
        self._expected = expected
        self._org_id = org_id

    def verify(self, token: str) -> TokenClaims:
        token = (token or "").strip()
        if not token:
            raise AuthError("missing bearer token")
        if self._expected and token != self._expected:
            raise AuthError("invalid bearer token")
        return TokenClaims(
            org_id=self._org_id,
            subject="dev",
            scopes=["verify", "match", "correlate"],
        )


class JwtTokenVerifier:
    """Production verifier: validate a signed JWT against the IdP JWKS.

    Enforces signature, expiry, issuer and (when configured) audience; reads the
    tenant from the first present org claim. Signing keys are resolved from the
    issuer's JWKS endpoint and cached by ``PyJWKClient``.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audience: str | None = None,
        jwks_uri: str | None = None,
        algorithms: tuple[str, ...] = ("RS256",),
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._audience = audience
        self._algorithms = list(algorithms)
        self._jwks_uri = jwks_uri or f"{self._issuer}/.well-known/jwks.json"
        self._jwk_client: Any = None

    def _client(self) -> Any:
        if self._jwk_client is None:
            from jwt import PyJWKClient

            self._jwk_client = PyJWKClient(self._jwks_uri)
        return self._jwk_client

    def verify(self, token: str) -> TokenClaims:
        import jwt

        token = (token or "").strip()
        if not token:
            raise AuthError("missing bearer token")
        try:
            signing_key = self._client().get_signing_key_from_jwt(token).key
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self._algorithms,
                issuer=self._issuer,
                audience=self._audience or None,
                options={
                    "require": ["exp"],
                    "verify_aud": bool(self._audience),
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthError(f"token verification failed: {type(exc).__name__}") from exc

        org_id = _first_org_claim(claims)
        if not org_id:
            raise AuthError("token missing org/tenant claim")
        return TokenClaims(
            org_id=org_id,
            subject=claims.get("sub"),
            scopes=_as_scopes(claims.get("scope") or claims.get("scopes")),
            expires_at=claims.get("exp"),
            issuer=claims.get("iss"),
        )


def default_verifier() -> TokenVerifier:
    """Build the configured token verifier (the swap point).

    Production: set ``ARGUS_OIDC_ISSUER`` (and optionally ``ARGUS_OIDC_AUDIENCE``
    / ``ARGUS_OIDC_JWKS_URI``) to verify real signed tokens against the IdP.
    Otherwise the static dev verifier is used (honouring ``ARGUS_TOKEN`` if set).
    """
    issuer = os.environ.get("ARGUS_OIDC_ISSUER")
    if issuer:
        return JwtTokenVerifier(
            issuer=issuer,
            audience=os.environ.get("ARGUS_OIDC_AUDIENCE"),
            jwks_uri=os.environ.get("ARGUS_OIDC_JWKS_URI"),
        )
    return StaticTokenVerifier(expected=os.environ.get("ARGUS_TOKEN"))


_verifier: TokenVerifier | None = None


def get_verifier() -> TokenVerifier:
    """Return the process-wide verifier, built once (so JWKS keys are cached)."""
    global _verifier
    if _verifier is None:
        _verifier = default_verifier()
    return _verifier


def reset_verifier() -> None:
    """Drop the cached verifier so the next call rebuilds it (tests / reconfig)."""
    global _verifier
    _verifier = None
