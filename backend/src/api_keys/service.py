"""API key service — token generation, persistence, and lookup.

All DB operations use run_db() (background thread + dedicated engine) to avoid
event-loop conflicts when called from synchronous code or during test runs.
"""
from __future__ import annotations

import base64
import hashlib
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from src.api_keys.models import ApiKey, ApiKeyRecord
from src.db.helpers import run_db

_TOKEN_PREFIX = "ak_live_"


def _generate_token() -> str:
    """Return a new API token: ak_live_<32-char base32-lowercase>."""
    raw = os.urandom(20)
    encoded = base64.b32encode(raw).decode().lower()[:32]
    return f"{_TOKEN_PREFIX}{encoded}"


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ── Synchronous DB operations ─────────────────────────────────────────────────

def _create_sync(
    org_id: str,
    name: str,
    scopes: list[str],
    created_by: str | None,
    expires_in_days: int | None,
) -> tuple[ApiKeyRecord, str]:
    """Create a new API key. Returns (record, plain_token)."""
    token = _generate_token()
    token_hash = _hash_token(token)
    prefix = _TOKEN_PREFIX
    last_four = token[-4:]

    expires_at: datetime | None = None
    if expires_in_days is not None:
        expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

    async def _run(session):
        row = ApiKey(
            org_id=org_id,
            name=name,
            prefix=prefix,
            last_four=last_four,
            token_hash=token_hash,
            scopes=scopes,
            created_by=created_by,
            expires_at=expires_at,
        )
        session.add(row)
        await session.flush()
        await session.refresh(row)
        return ApiKeyRecord.from_orm(row)

    record = run_db(_run)
    return record, token


def _list_sync(org_id: str) -> list[ApiKeyRecord]:
    async def _run(session):
        result = await session.execute(
            select(ApiKey)
            .where(ApiKey.org_id == org_id)
            .order_by(ApiKey.created_at.desc())
        )
        return [ApiKeyRecord.from_orm(r) for r in result.scalars().all()]

    return run_db(_run)


def _revoke_sync(key_id: int, org_id: str) -> ApiKeyRecord | None:
    async def _run(session):
        row = await session.get(ApiKey, key_id)
        if row is None or row.org_id != org_id:
            return None
        row.revoked_at = datetime.now(timezone.utc)
        await session.flush()
        await session.refresh(row)
        return ApiKeyRecord.from_orm(row)

    return run_db(_run)


def _lookup_by_token_sync(token: str) -> "ApiKey | None":
    token_hash = _hash_token(token)

    async def _run(session):
        result = await session.execute(
            select(ApiKey).where(ApiKey.token_hash == token_hash)
        )
        return result.scalar_one_or_none()

    return run_db(_run)


def _record_usage_sync(key_id: int) -> None:
    async def _run(session):
        row = await session.get(ApiKey, key_id)
        if row is not None:
            row.last_used_at = datetime.now(timezone.utc)

    try:
        run_db(_run)
    except Exception:
        pass  # usage recording is best-effort


# ── Async wrappers for FastAPI routes ─────────────────────────────────────────

async def create(
    org_id: str,
    name: str,
    scopes: list[str],
    created_by: str | None,
    expires_in_days: int | None,
) -> tuple[ApiKeyRecord, str]:
    return _create_sync(org_id, name, scopes, created_by, expires_in_days)


async def list_keys(org_id: str) -> list[ApiKeyRecord]:
    return _list_sync(org_id)


async def revoke(key_id: int, org_id: str) -> ApiKeyRecord | None:
    return _revoke_sync(key_id, org_id)


async def lookup_by_token(token: str) -> "ApiKey | None":
    return _lookup_by_token_sync(token)


async def record_usage(key_id: int) -> None:
    _record_usage_sync(key_id)
