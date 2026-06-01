"""Tests for VerifiedSecretsCache — get/put/invalidate against real Postgres."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete as sa_delete

from src.secrets.verified_secrets_cache import VerifiedSecretsCache, VerificationStatus
from src.db.helpers import run_db
from src.db.models import VerifiedSecret


DETECTOR_A = "trufflehog@3.82.1::AWS"
DETECTOR_B = "trufflehog@3.82.1::GitHub"
HASH_1 = "a" * 64
HASH_2 = "b" * 64


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(sa_delete(VerifiedSecret))
    run_db(_del)
    yield


# ── get returns None on miss ──────────────────────────────────────────────────


def test_get_returns_none_on_miss():
    cache = VerifiedSecretsCache()
    result = cache.get(DETECTOR_A, HASH_1)
    assert result is None


# ── put then get ─────────────────────────────────────────────────────────────


def test_put_then_get_returns_status():
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="verified")

    result = cache.get(DETECTOR_A, HASH_1)
    assert result is not None
    assert isinstance(result, VerificationStatus)
    assert result.status == "verified"


def test_put_then_get_ttl_until_is_in_future():
    cache = VerifiedSecretsCache(ttl_seconds=3600)
    cache.put(DETECTOR_A, HASH_1, status="unverified")

    result = cache.get(DETECTOR_A, HASH_1)
    assert result is not None
    assert result.ttl_until > datetime.now(timezone.utc)


def test_put_with_custom_ttl_overrides_default():
    cache = VerifiedSecretsCache(ttl_seconds=3600)
    cache.put(DETECTOR_A, HASH_1, status="unverified", ttl_seconds=100)

    result = cache.get(DETECTOR_A, HASH_1)
    assert result is not None
    # TTL should be ~100s, well under the default 3600s
    delta = result.ttl_until - datetime.now(timezone.utc)
    assert delta.total_seconds() < 200


# ── TTL expiry ────────────────────────────────────────────────────────────────


def test_expired_entry_returns_none():
    """An entry with ttl_until in the past should be treated as a miss."""
    cache = VerifiedSecretsCache()
    # Put with 1-second TTL then manually backdate the row
    cache.put(DETECTOR_A, HASH_1, status="verified", ttl_seconds=1)

    # Backdate the row past expiry
    async def _expire(session):
        from sqlalchemy import update
        await session.execute(
            update(VerifiedSecret)
            .where(VerifiedSecret.detector_id == DETECTOR_A, VerifiedSecret.secret_hash == HASH_1)
            .values(ttl_until=datetime.now(timezone.utc) - timedelta(seconds=10))
        )
    run_db(_expire)

    result = cache.get(DETECTOR_A, HASH_1)
    assert result is None


# ── idempotent upsert ─────────────────────────────────────────────────────────


def test_put_twice_upserts_not_duplicates():
    """Calling put twice for the same key must not raise and must return latest."""
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="unverified")
    cache.put(DETECTOR_A, HASH_1, status="verified")

    result = cache.get(DETECTOR_A, HASH_1)
    assert result is not None
    assert result.status == "verified"

    # Confirm only one row exists
    async def _count(session):
        from sqlalchemy import select, func
        r = await session.execute(
            select(func.count()).select_from(VerifiedSecret).where(
                VerifiedSecret.detector_id == DETECTOR_A,
                VerifiedSecret.secret_hash == HASH_1,
            )
        )
        return r.scalar()

    assert run_db(_count) == 1


# ── different (detector_id, secret_hash) pairs are independent ───────────────


def test_different_detector_ids_are_independent():
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="verified")
    cache.put(DETECTOR_B, HASH_1, status="revoked")

    assert cache.get(DETECTOR_A, HASH_1).status == "verified"
    assert cache.get(DETECTOR_B, HASH_1).status == "revoked"


def test_different_secret_hashes_are_independent():
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="verified")
    cache.put(DETECTOR_A, HASH_2, status="unreachable")

    assert cache.get(DETECTOR_A, HASH_1).status == "verified"
    assert cache.get(DETECTOR_A, HASH_2).status == "unreachable"


# ── invalidate ────────────────────────────────────────────────────────────────


def test_invalidate_removes_entry():
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="verified")
    cache.invalidate(DETECTOR_A, HASH_1)

    assert cache.get(DETECTOR_A, HASH_1) is None


def test_invalidate_is_idempotent():
    """Invalidating a non-existent entry should not raise."""
    cache = VerifiedSecretsCache()
    cache.invalidate(DETECTOR_A, "nonexistent_hash")


def test_invalidate_only_removes_matching_key():
    cache = VerifiedSecretsCache()
    cache.put(DETECTOR_A, HASH_1, status="verified")
    cache.put(DETECTOR_A, HASH_2, status="unverified")

    cache.invalidate(DETECTOR_A, HASH_1)

    assert cache.get(DETECTOR_A, HASH_1) is None
    assert cache.get(DETECTOR_A, HASH_2) is not None
