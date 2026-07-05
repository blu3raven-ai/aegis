"""API key authentication — token verification with timing-safe comparison."""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Protocol

_TOKEN_PREFIX = "ak_"


class _ScopedKey(Protocol):
    scopes: list[str]
    allowed_source_ids: list[str] | None


def _verify_sync(authorization_header: str | None) -> object | None:
    """Verify a Bearer token as an API key. Returns the ApiKey row or None.

    Uses hmac.compare_digest to prevent timing attacks.
    """
    if not authorization_header or not authorization_header.startswith("Bearer "):
        return None

    token = authorization_header.split(" ", 1)[1]
    if not token.startswith(_TOKEN_PREFIX):
        return None

    candidate_hash = hashlib.sha256(token.encode()).hexdigest()

    # Lazy imports keep DB engine initialisation out of module load time,
    # allowing pure helper functions in this module to be imported without
    # a live DATABASE_URL (e.g. in unit tests).
    from sqlalchemy import select

    from src.db.helpers import run_db
    from src.db.models import ApiKey

    async def _run(session):
        result = await session.execute(
            select(ApiKey).where(ApiKey.token_hash == candidate_hash)
        )
        return result.scalar_one_or_none()

    try:
        row = run_db(_run)
    except Exception:
        return None

    if row is None:
        return None

    if not hmac.compare_digest(candidate_hash, row.token_hash):
        return None

    if row.revoked_at is not None:
        return None

    if row.expires_at is not None and row.expires_at < datetime.now(timezone.utc):
        return None

    return row


async def verify_api_key(authorization_header: str | None) -> object | None:
    """Async wrapper around _verify_sync."""
    return _verify_sync(authorization_header)


def require_scope_and_source(
    api_key: _ScopedKey,
    *,
    scope: str,
    source_id: str,
) -> dict | None:
    """Return None if the key carries the required scope and is allowed to act on source_id.

    Otherwise return a small dict the caller can serialize directly into a 403 body.
    `allowed_source_ids` of None or an empty list is treated as unrestricted.
    """
    scopes = getattr(api_key, "scopes", None) or []
    if scope not in scopes:
        return {"error": "missing_scope", "missing_scope": scope}

    allowed = getattr(api_key, "allowed_source_ids", None)
    if allowed:  # non-empty list — enforce allowlist
        if source_id not in allowed:
            return {"error": "source_not_in_scope", "source_id": source_id}

    return None
