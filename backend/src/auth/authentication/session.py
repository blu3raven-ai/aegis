"""Server-side session lifecycle.

Sessions are opaque IDs (256-bit random, base64url) stored in the
user_sessions table. Lookups verify `revoked_at IS NULL AND expires_at > now()`.
"""
from __future__ import annotations

import secrets
from datetime import timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import UserSession, utcnow

EXPIRED_RETENTION_DAYS = 30
DEFAULT_TTL_SECONDS = 8 * 3600  # 8h sliding session


def _generate_session_id() -> str:
    """Return a base64url-encoded 32-byte random ID (43 chars, ~256 bits)."""
    return secrets.token_urlsafe(32)


class SessionService:
    """Server-side session lifecycle. The CALLER owns the transaction —
    every method calls `flush()` not `commit()` so revoke + create + audit
    sequences can be atomic in a single unit of work. Wrap call sites in
    `async with db.begin():` or rely on the FastAPI dependency that yields
    a session and commits on success.
    """

    def __init__(self, db: AsyncSession, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.db = db
        self.ttl_seconds = ttl_seconds

    async def create(
        self,
        *,
        user_id: str,
        user_agent: str | None,
        ip_address: str | None,
    ) -> UserSession:
        now = utcnow()
        sess = UserSession(
            id=_generate_session_id(),
            user_id=user_id,
            created_at=now,
            last_seen_at=now,
            expires_at=now + timedelta(seconds=self.ttl_seconds),
            user_agent=user_agent,
            ip_address=ip_address,
        )
        self.db.add(sess)
        await self.db.flush()
        return sess

    async def lookup(self, session_id: str) -> UserSession | None:
        if not session_id:
            return None
        result = await self.db.execute(
            select(UserSession).where(
                UserSession.id == session_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > utcnow(),
            )
        )
        return result.scalar_one_or_none()

    async def touch(self, session_id: str) -> UserSession | None:
        if not session_id:
            return None
        now = utcnow()
        new_expiry = now + timedelta(seconds=self.ttl_seconds)
        result = await self.db.execute(
            update(UserSession)
            .where(
                UserSession.id == session_id,
                UserSession.revoked_at.is_(None),
                UserSession.expires_at > now,
            )
            .values(last_seen_at=now, expires_at=new_expiry)
            .returning(UserSession)
        )
        sess = result.scalar_one_or_none()
        await self.db.flush()
        return sess

    async def revoke(self, session_id: str, *, reason: str) -> bool:
        """Mark a session as revoked. Returns True if revoked, False if not found or already revoked."""
        result = await self.db.execute(
            update(UserSession)
            .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
            .values(revoked_at=utcnow(), revocation_reason=reason)
        )
        await self.db.flush()
        return result.rowcount > 0

    async def revoke_all_for_user(
        self,
        *,
        user_id: str,
        except_session_id: str | None,
        reason: str,
    ) -> int:
        query = update(UserSession).where(
            UserSession.user_id == user_id,
            UserSession.revoked_at.is_(None),
        )
        if except_session_id is not None:
            query = query.where(UserSession.id != except_session_id)
        query = query.values(revoked_at=utcnow(), revocation_reason=reason)

        result = await self.db.execute(query)
        await self.db.flush()
        return result.rowcount or 0

    async def purge_expired(self) -> int:
        """Hard-delete sessions whose `expires_at` is more than EXPIRED_RETENTION_DAYS ago.
        Retention exists so we can still answer 'was session X used?' for incident review.
        """
        cutoff = utcnow() - timedelta(days=EXPIRED_RETENTION_DAYS)
        result = await self.db.execute(
            delete(UserSession).where(UserSession.expires_at < cutoff)
        )
        await self.db.flush()
        return result.rowcount or 0
