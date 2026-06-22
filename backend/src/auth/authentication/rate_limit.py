"""Sliding-window rate limit backed by Postgres rate_limit_buckets.

Atomic INSERT ... ON CONFLICT DO UPDATE keeps the increment and the
window-reset race-free without external coordination.
A bucket whose window_start is older than `now - window_seconds` is reset
to fresh; otherwise its counter is incremented in the same statement.

**Postgres only.** The ON CONFLICT semantics this relies on are Postgres-
specific; this service cannot be used with SQLite or other dialects.

The CALLER owns the transaction — `check_and_record` flushes the change
but does not commit (consistent with SessionService).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import utcnow as _utcnow

# Matches the rate_limit_buckets.key column length (see db.models.RateLimitBucket).
_MAX_KEY_LEN = 512


class RateLimitService:
    """Per-key sliding-window counter. The caller owns the transaction;
    `check_and_record` flushes the change so subsequent statements in the
    same unit of work observe it.
    """

    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def check_and_record(
        self, *, key: str, limit: int, window_seconds: int
    ) -> bool:
        """Atomically increment counter and report whether request is permitted.

        Returns True if under or at the limit (request allowed), False otherwise.
        """
        if not key:
            raise ValueError("key must be non-empty")
        if len(key) > _MAX_KEY_LEN:
            raise ValueError(f"key must be ≤{_MAX_KEY_LEN} chars")
        if limit <= 0:
            raise ValueError("limit must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")

        now = _utcnow()
        cutoff = now - timedelta(seconds=window_seconds)

        result = await self.db.execute(
            text(
                """
                INSERT INTO rate_limit_buckets (key, window_start, request_count, updated_at)
                VALUES (:key, :now, 1, :now)
                ON CONFLICT (key) DO UPDATE
                SET
                    window_start  = CASE
                                      WHEN rate_limit_buckets.window_start < :cutoff
                                        THEN EXCLUDED.window_start
                                      ELSE rate_limit_buckets.window_start
                                    END,
                    request_count = CASE
                                      WHEN rate_limit_buckets.window_start < :cutoff
                                        THEN 1
                                      ELSE rate_limit_buckets.request_count + 1
                                    END,
                    updated_at    = :now
                RETURNING request_count
                """
            ),
            {"key": key, "now": now, "cutoff": cutoff},
        )
        # NOTE: across concurrent writers crossing the window boundary, the
        # bucket's window_start may end up at the latest :now seen rather than
        # the earliest. This is a microsecond-level skew that's harmless for
        # rate-limiting purposes — the window still spans `window_seconds`,
        # it just starts a tick later than ideal.
        await self.db.flush()
        count = result.scalar_one()
        return count <= limit
