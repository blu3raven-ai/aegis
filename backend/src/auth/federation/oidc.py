"""authlib OIDC client wrapper for the Aegis SSO flow."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.jose import jwt

from src.db.models import SsoConfig
from src.security.crypto import decrypt


@dataclass
class OidcIdentity:
    subject: str
    email: str
    name: str


async def _discovery(discovery_url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
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

    async with httpx.AsyncClient(timeout=10.0) as http:
        jwks_resp = await http.get(disc["jwks_uri"])
        jwks_resp.raise_for_status()
        jwks = jwks_resp.json()

    claims = jwt.decode(id_token, jwks)
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
    return OidcIdentity(subject=sub, email=email, name=name)
