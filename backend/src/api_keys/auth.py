"""API key authentication — token verification with timing-safe comparison."""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from src.db.helpers import run_db

_TOKEN_PREFIX = "ak_"


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

    from sqlalchemy import select
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
