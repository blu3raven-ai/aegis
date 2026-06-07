"""Sliding-window rate-limit tests.

These hit a real Postgres via the existing test fixtures (db_session, etc.)
so they exercise the atomic INSERT ... ON CONFLICT path, not just Python logic.
"""
from __future__ import annotations

import datetime as dt
from uuid import uuid4

import pytest
import pytest_asyncio

from src.auth.rate_limit import RateLimitService
from src.db.models import RateLimitBucket


@pytest_asyncio.fixture
async def rate_limit_service(db_session):
    """Yield a RateLimitService bound to the test session, and clean up our keys."""
    svc = RateLimitService(db=db_session)
    yield svc

    # Cleanup: only the rows this file created
    from sqlalchemy import delete
    await db_session.execute(
        delete(RateLimitBucket).where(RateLimitBucket.key.like("test:%"))
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_first_request_allowed(rate_limit_service):
    key = f"test:first:{uuid4()}"
    assert await rate_limit_service.check_and_record(
        key=key, limit=5, window_seconds=60
    ) is True


@pytest.mark.asyncio
async def test_within_limit_allowed(rate_limit_service):
    key = f"test:within:{uuid4()}"
    for _ in range(5):
        assert await rate_limit_service.check_and_record(
            key=key, limit=5, window_seconds=60
        ) is True


@pytest.mark.asyncio
async def test_over_limit_blocked(rate_limit_service):
    key = f"test:over:{uuid4()}"
    for _ in range(5):
        await rate_limit_service.check_and_record(
            key=key, limit=5, window_seconds=60
        )
    blocked = await rate_limit_service.check_and_record(
        key=key, limit=5, window_seconds=60
    )
    assert blocked is False


@pytest.mark.asyncio
async def test_separate_keys_separate_buckets(rate_limit_service):
    ka = f"test:ka:{uuid4()}"
    kb = f"test:kb:{uuid4()}"
    for _ in range(5):
        await rate_limit_service.check_and_record(
            key=ka, limit=5, window_seconds=60
        )
    # ka is full, kb should still have fresh budget
    assert await rate_limit_service.check_and_record(
        key=kb, limit=5, window_seconds=60
    ) is True


@pytest.mark.asyncio
async def test_window_resets_after_expiry(rate_limit_service, monkeypatch):
    """Once window_seconds elapses, the bucket resets and traffic resumes."""
    from src.auth import rate_limit as rl_mod

    now = dt.datetime(2026, 6, 2, 12, 0, 0, tzinfo=dt.timezone.utc)
    monkeypatch.setattr(rl_mod, "_utcnow", lambda: now)

    key = f"test:reset:{uuid4()}"
    for _ in range(5):
        await rate_limit_service.check_and_record(
            key=key, limit=5, window_seconds=60
        )

    # Advance time past the window
    monkeypatch.setattr(rl_mod, "_utcnow", lambda: now + dt.timedelta(seconds=61))
    assert await rate_limit_service.check_and_record(
        key=key, limit=5, window_seconds=60
    ) is True


@pytest.mark.asyncio
async def test_check_and_record_rejects_empty_key(rate_limit_service):
    with pytest.raises(ValueError, match="key must be non-empty"):
        await rate_limit_service.check_and_record(key="", limit=5, window_seconds=60)


@pytest.mark.asyncio
async def test_check_and_record_rejects_oversized_key(rate_limit_service):
    big_key = "x" * 513
    with pytest.raises(ValueError, match="key must be ≤512 chars"):
        await rate_limit_service.check_and_record(key=big_key, limit=5, window_seconds=60)


@pytest.mark.asyncio
async def test_check_and_record_rejects_non_positive_limit(rate_limit_service):
    with pytest.raises(ValueError, match="limit must be positive"):
        await rate_limit_service.check_and_record(key="t", limit=0, window_seconds=60)


@pytest.mark.asyncio
async def test_check_and_record_rejects_negative_window(rate_limit_service):
    with pytest.raises(ValueError, match="window_seconds must be positive"):
        await rate_limit_service.check_and_record(key="t", limit=5, window_seconds=-1)
