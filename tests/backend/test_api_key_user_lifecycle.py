"""A disabled user's API key must not authenticate.

The disable path revokes the key row; the verify path also defense-in-depth
checks the creator's status so a straggler key can't survive.
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from uuid import uuid4

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest
from sqlalchemy import delete

from src.auth.credentials.auth import verify_api_key
from src.db.helpers import run_db
from src.db.models import ApiKey, User

_TOKEN = "ak_live_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"


def _seed(creator_id: str, *, status: str = "active") -> None:
    async def _q(session):
        session.add(User(
            id=creator_id, username=creator_id, email=f"{creator_id}@example.com",
            password_hash="", status=status,
        ))
        await session.flush()  # ensure the creator row exists before the FK ref
        session.add(ApiKey(
            name="k", prefix="ak_live", last_four="zzzz",
            token_hash=hashlib.sha256(_TOKEN.encode()).hexdigest(),
            scopes=["scan:trigger"], created_by=creator_id,
            created_by_user_id=creator_id,
        ))

    run_db(_q)


def _cleanup(prefix: str) -> None:
    async def _q(session):
        await session.execute(delete(ApiKey).where(ApiKey.created_by_user_id.like(f"{prefix}%")))
        await session.execute(delete(User).where(User.id.like(f"{prefix}%")))

    run_db(_q)


@pytest.mark.asyncio
async def test_active_creator_key_authenticates():
    cid = f"kkey-{uuid4().hex[:8]}"
    _seed(cid, status="active")
    try:
        row = await verify_api_key(f"Bearer {_TOKEN}")
        assert row is not None
    finally:
        _cleanup(cid)


@pytest.mark.asyncio
async def test_disabled_creator_key_rejected():
    cid = f"kkey-{uuid4().hex[:8]}"
    _seed(cid, status="disabled")
    try:
        # Even with the row un-revoked (simulating a revoke race), the verify
        # path must reject because the creator is disabled.
        row = await verify_api_key(f"Bearer {_TOKEN}")
        assert row is None
    finally:
        _cleanup(cid)
