"""Per-org connection to the hosted Argus threat-intel enrichment service.

The durable credential is an OAuth2 refresh token, stored encrypted at rest.
Short-lived access tokens are minted on demand by the backend threat-intel match
path via the standard refresh-token grant, so a leaked secret is never long-lived.
"""
from __future__ import annotations

from dataclasses import dataclass

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import ArgusConnection
from src.security.crypto import decrypt, encrypt
from src.shared.url_guard import UnsafeURLError, assert_sendable_url

_TOKEN_TIMEOUT = 15.0


class ArgusAuthError(Exception):
    """Raised when the OAuth refresh-token exchange with Argus fails.

    Messages never echo the refresh or access token.
    """


@dataclass
class ArgusConnectionDTO:
    endpoint: str
    token_endpoint: str
    client_id: str
    refresh_token: str
    enabled: bool


async def fetch_argus_connection(
    session: AsyncSession, org_id: str
) -> ArgusConnectionDTO | None:
    """Load the org's Argus connection, decrypting the stored refresh token."""
    row = (
        await session.execute(
            select(ArgusConnection).where(ArgusConnection.org_id == org_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return None
    return ArgusConnectionDTO(
        endpoint=row.endpoint,
        token_endpoint=row.token_endpoint,
        client_id=row.client_id,
        refresh_token=decrypt(row.refresh_token_enc) or "",
        enabled=row.enabled,
    )


async def upsert_argus_connection(
    session: AsyncSession,
    org_id: str,
    *,
    endpoint: str,
    token_endpoint: str,
    client_id: str,
    refresh_token: str,
    enabled: bool,
) -> ArgusConnectionDTO:
    """Create or update the org's Argus connection, encrypting the refresh token."""
    refresh_token_enc = encrypt(refresh_token)
    row = (
        await session.execute(
            select(ArgusConnection).where(ArgusConnection.org_id == org_id)
        )
    ).scalar_one_or_none()
    if row is None:
        session.add(
            ArgusConnection(
                org_id=org_id,
                endpoint=endpoint,
                token_endpoint=token_endpoint,
                client_id=client_id,
                refresh_token_enc=refresh_token_enc,
                enabled=enabled,
            )
        )
    else:
        row.endpoint = endpoint
        row.token_endpoint = token_endpoint
        row.client_id = client_id
        row.refresh_token_enc = refresh_token_enc
        row.enabled = enabled
    return ArgusConnectionDTO(
        endpoint=endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        refresh_token=refresh_token,
        enabled=enabled,
    )


async def delete_argus_connection(session: AsyncSession, org_id: str) -> bool:
    """Remove the org's Argus connection. Returns True if a row was deleted."""
    row = (
        await session.execute(
            select(ArgusConnection).where(ArgusConnection.org_id == org_id)
        )
    ).scalar_one_or_none()
    if row is None:
        return False
    await session.delete(row)
    return True


def mint_argus_access_token(conn: ArgusConnectionDTO) -> str:
    """Exchange the stored refresh token for a fresh short-lived access token.

    Uses the OAuth2 refresh-token grant against ``conn.token_endpoint``. The
    token is minted fresh on every call (no caching) and is short-lived, so it
    is safe to ship to the runner (encrypted in transit). Raises ArgusAuthError
    on transport failure, a non-200 response, or a response missing
    ``access_token`` — without ever echoing the refresh token.

    Synchronous so it can be called from the sync scan-dispatch + settings
    routes (a single bounded HTTP call).
    """
    # token_endpoint is admin-supplied config — block SSRF to internal hosts.
    try:
        assert_sendable_url(conn.token_endpoint)
    except UnsafeURLError as exc:
        raise ArgusAuthError(f"unsafe argus token endpoint: {exc}") from exc
    try:
        with httpx.Client(timeout=_TOKEN_TIMEOUT, follow_redirects=False) as client:
            resp = client.post(
                conn.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": conn.refresh_token,
                    "client_id": conn.client_id,
                },
            )
    except httpx.HTTPError as exc:
        raise ArgusAuthError(f"argus token endpoint unreachable: {type(exc).__name__}") from exc

    if resp.status_code != 200:
        raise ArgusAuthError(f"argus token exchange failed: HTTP {resp.status_code}")

    try:
        access_token = resp.json().get("access_token")
    except ValueError as exc:
        raise ArgusAuthError("argus token response was not valid JSON") from exc

    if not access_token:
        raise ArgusAuthError("argus token response missing access_token")
    return access_token
