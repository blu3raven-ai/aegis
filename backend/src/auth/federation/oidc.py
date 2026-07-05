"""authlib OIDC client wrapper for the Aegis SSO flow."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import JsonWebToken

from src.db.models import SsoConfig
from src.security.crypto import decrypt
from src.shared.url_guard import assert_sendable_url

# Restrict id_token verification to asymmetric signatures. Excluding `none`
# and the HS* family prevents an attacker from forging a token signed with a
# symmetric key derived from a public value (or with no signature at all).
_ID_TOKEN_ALGS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]
_jwt = JsonWebToken(_ID_TOKEN_ALGS)


@dataclass
class OidcIdentity:
    subject: str
    email: str
    name: str
    email_verified: bool


def _is_email_verified(raw: Any) -> bool:
    """Whether the IdP positively asserted the email as verified.

    Per OIDC `email_verified` is a JSON boolean, but some IdPs emit the string
    "true". Anything else (including absent) is treated as unverified so the
    email cannot be used to link a pre-existing account.
    """
    if raw is True:
        return True
    if isinstance(raw, str):
        return raw.strip().lower() == "true"
    return False


async def _discovery(discovery_url: str) -> dict[str, Any]:
    # The discovery URL is admin-supplied config — block SSRF to internal hosts.
    assert_sendable_url(discovery_url)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
        return resp.json()


def _client_secret(row: SsoConfig) -> str:
    secret = decrypt(row.oidc_client_secret_enc)
    if secret is None:
        raise RuntimeError("OIDC client secret is not configured.")
    return secret


async def authorize_url(row: SsoConfig, redirect_uri: str, state: str, nonce: str) -> str:
    if not row.oidc_discovery_url or not row.oidc_client_id:
        raise RuntimeError("OIDC is not configured.")
    disc = await _discovery(row.oidc_discovery_url)
    client = AsyncOAuth2Client(
        client_id=row.oidc_client_id,
        scope=row.oidc_scopes or "openid email profile",
        redirect_uri=redirect_uri,
    )
    url, _ = client.create_authorization_url(
        disc["authorization_endpoint"],
        state=state,
        nonce=nonce,
    )
    return url


async def exchange_code(row: SsoConfig, redirect_uri: str, code: str, expected_nonce: str) -> OidcIdentity:
    if not row.oidc_discovery_url or not row.oidc_client_id:
        raise RuntimeError("OIDC is not configured.")
    disc = await _discovery(row.oidc_discovery_url)
    client = AsyncOAuth2Client(
        client_id=row.oidc_client_id,
        client_secret=_client_secret(row),
        redirect_uri=redirect_uri,
    )
    token = await client.fetch_token(
        disc["token_endpoint"],
        code=code,
        grant_type="authorization_code",
    )
    id_token = token.get("id_token")
    if not id_token:
        raise RuntimeError("OIDC token response missing id_token.")

    # jwks_uri comes from the (now guarded) discovery doc; guard it too as
    # defense-in-depth so a compromised IdP can't redirect the fetch inward.
    assert_sendable_url(disc["jwks_uri"])
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as http:
        jwks_resp = await http.get(disc["jwks_uri"])
        jwks_resp.raise_for_status()
        jwks = jwks_resp.json()

    issuer = disc.get("issuer")
    if not issuer:
        raise RuntimeError("OIDC discovery document is missing the issuer.")

    # Bind the id_token to this RP: `iss` must equal the discovery issuer and
    # `aud` must equal our client id, so a token minted for a different client
    # at the same (multi-tenant) issuer is rejected. authlib only enforces
    # these when the expected values are supplied via claims_options.
    claims = _jwt.decode(
        id_token,
        jwks,
        claims_options={
            "iss": {"essential": True, "value": issuer},
            "aud": {"essential": True, "value": row.oidc_client_id},
        },
    )
    claims.validate()
    if claims.get("nonce") != expected_nonce:
        raise RuntimeError("OIDC nonce mismatch.")

    sub = str(claims.get("sub") or "")
    email = str(claims.get("email") or "")
    name = str(claims.get("name") or claims.get("preferred_username") or email)
    if not sub:
        raise RuntimeError("OIDC id_token missing sub claim.")
    if not email:
        raise RuntimeError("OIDC id_token missing email claim.")
    return OidcIdentity(
        subject=sub,
        email=email,
        name=name,
        email_verified=_is_email_verified(claims.get("email_verified")),
    )
