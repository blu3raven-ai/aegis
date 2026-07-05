"""Tests for UserSession / RateLimitBucket model wiring and SessionService."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import update

from src.db.models import RateLimitBucket, UserSession


def test_user_session_columns():
    cols = {c.name for c in UserSession.__table__.columns}
    assert cols == {
        "id",
        "user_id",
        "created_at",
        "last_seen_at",
        "expires_at",
        "user_agent",
        "ip_address",
        "revoked_at",
        "revocation_reason",
    }


def test_rate_limit_bucket_columns():
    cols = {c.name for c in RateLimitBucket.__table__.columns}
    assert cols == {"key", "window_start", "request_count", "updated_at"}



from src.auth.authentication.session import SessionService  # noqa: E402


@pytest_asyncio.fixture
async def session_service(db_session, seed_user):
    svc = SessionService(db=db_session, ttl_seconds=8 * 3600)
    yield svc, seed_user


@pytest.mark.asyncio
async def test_create_issues_opaque_256_bit_id(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    assert len(sess.id) == 43  # secrets.token_urlsafe(32) always returns exactly 43 chars
    assert sess.user_id == user.id
    assert sess.revoked_at is None
    assert sess.expires_at > datetime.now(timezone.utc)


@pytest.mark.asyncio
async def test_lookup_returns_active_session(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    found = await svc.lookup(sess.id)
    assert found is not None
    assert found.id == sess.id


@pytest.mark.asyncio
async def test_lookup_loads_user_relationship(session_service):
    """The gate reads session.user.status — the relationship must be eager-loaded."""
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    found = await svc.lookup(sess.id)
    assert found is not None
    # No additional DB query — the user is on the loaded session (lazy="joined")
    assert found.user.id == user.id
    assert found.user.status == user.status


@pytest.mark.asyncio
async def test_lookup_returns_none_for_revoked(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    await svc.revoke(sess.id, reason="logout")
    assert await svc.lookup(sess.id) is None


@pytest.mark.asyncio
async def test_lookup_returns_none_for_expired(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    await svc.db.execute(
        update(UserSession)
        .where(UserSession.id == sess.id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    )
    await svc.db.commit()
    assert await svc.lookup(sess.id) is None


@pytest.mark.asyncio
async def test_lookup_returns_none_for_empty_string(session_service):
    svc, _user = session_service
    assert await svc.lookup("") is None


@pytest.mark.asyncio
async def test_lookup_returns_none_for_unknown_id(session_service):
    svc, _user = session_service
    assert await svc.lookup("does-not-exist") is None


@pytest.mark.asyncio
async def test_touch_extends_expiry_and_last_seen(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    original_expiry = sess.expires_at
    original_last_seen = sess.last_seen_at

    await asyncio.sleep(0.01)

    refreshed = await svc.touch(sess.id)
    assert refreshed.last_seen_at > original_last_seen
    assert refreshed.expires_at > original_expiry


@pytest.mark.asyncio
async def test_touch_returns_none_for_revoked(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    await svc.revoke(sess.id, reason="logout")
    assert await svc.touch(sess.id) is None


@pytest.mark.asyncio
async def test_touch_returns_none_for_expired(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    await svc.db.execute(
        update(UserSession)
        .where(UserSession.id == sess.id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(minutes=1))
    )
    await svc.db.commit()  # test fixture explicitly commits its setup
    assert await svc.touch(sess.id) is None


@pytest.mark.asyncio
async def test_revoke_all_for_user_except(session_service):
    svc, user = session_service
    s1 = await svc.create(user_id=user.id, user_agent="A", ip_address="1.1.1.1")
    s2 = await svc.create(user_id=user.id, user_agent="B", ip_address="2.2.2.2")
    s3 = await svc.create(user_id=user.id, user_agent="C", ip_address="3.3.3.3")

    revoked = await svc.revoke_all_for_user(
        user_id=user.id, except_session_id=s2.id, reason="password_change"
    )
    assert revoked == 2

    assert await svc.lookup(s1.id) is None
    assert await svc.lookup(s2.id) is not None
    assert await svc.lookup(s3.id) is None


@pytest.mark.asyncio
async def test_revoke_all_for_user_with_no_except(session_service):
    svc, user = session_service
    s1 = await svc.create(user_id=user.id, user_agent="A", ip_address="1.1.1.1")
    s2 = await svc.create(user_id=user.id, user_agent="B", ip_address="2.2.2.2")

    revoked = await svc.revoke_all_for_user(
        user_id=user.id, except_session_id=None, reason="admin_revoke"
    )
    assert revoked == 2
    assert await svc.lookup(s1.id) is None
    assert await svc.lookup(s2.id) is None


@pytest.mark.asyncio
async def test_revoke_returns_false_for_unknown_session(session_service):
    svc, _user = session_service
    revoked = await svc.revoke("nonexistent-id", reason="logout")
    assert revoked is False


@pytest.mark.asyncio
async def test_revoke_returns_false_for_already_revoked(session_service):
    svc, user = session_service
    sess = await svc.create(user_id=user.id, user_agent="ua", ip_address="1.2.3.4")
    first = await svc.revoke(sess.id, reason="logout")
    second = await svc.revoke(sess.id, reason="logout")
    assert first is True
    assert second is False


@pytest.mark.asyncio
async def test_purge_expired_removes_only_expired(session_service):
    svc, user = session_service
    s_active = await svc.create(user_id=user.id, user_agent="A", ip_address="1.1.1.1")
    s_expired = await svc.create(user_id=user.id, user_agent="B", ip_address="2.2.2.2")
    await svc.db.execute(
        update(UserSession)
        .where(UserSession.id == s_expired.id)
        .values(expires_at=datetime.now(timezone.utc) - timedelta(days=31))
    )
    await svc.db.commit()

    purged = await svc.purge_expired()
    assert purged == 1
    assert await svc.lookup(s_active.id) is not None


@pytest.mark.asyncio
async def test_purge_expired_returns_zero_when_none_expired(session_service):
    svc, _user = session_service
    assert await svc.purge_expired() == 0
