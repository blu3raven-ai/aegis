"""Verified-secrets cache backed by the verified_secrets Postgres table.

Phase 2d: live verification (TruffleHog subprocess) is expensive. This cache
lets repeated scans skip re-verification when the result is still within TTL.
The default TTL of 7 days balances staleness risk against verification cost —
revoked secrets are caught on the next weekly full sweep even if a push-path
scan skips re-verification.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import VerifiedSecret

_DEFAULT_TTL_SECONDS = 7 * 24 * 3600


@dataclass
class VerificationStatus:
    status: str          # "verified" | "unverified" | "revoked" | "unreachable"
    verified_at: datetime
    ttl_until: datetime


class VerifiedSecretsCache:
    """Read/write verified-secret results with TTL-based expiration."""

    def __init__(
        self,
        session_factory=None,          # unused — kept for API symmetry with other caches
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._default_ttl = ttl_seconds

    def get(self, detector_id: str, secret_hash: str) -> VerificationStatus | None:
        """Return cached status if present and not expired, else None."""
        now = datetime.now(timezone.utc)

        async def _fetch(session):
            result = await session.execute(
                select(VerifiedSecret).where(
                    VerifiedSecret.detector_id == detector_id,
                    VerifiedSecret.secret_hash == secret_hash,
                )
            )
            return result.scalars().first()

        row = run_db(_fetch)
        if row is None:
            return None
        # Treat expired entries as misses so the caller re-verifies
        if row.ttl_until.replace(tzinfo=timezone.utc) < now:
            return None
        return VerificationStatus(
            status=row.status,
            verified_at=row.verified_at.replace(tzinfo=timezone.utc),
            ttl_until=row.ttl_until.replace(tzinfo=timezone.utc),
        )

    def put(
        self,
        detector_id: str,
        secret_hash: str,
        *,
        status: str,
        ttl_seconds: int | None = None,
    ) -> None:
        """Upsert a verification result. ON CONFLICT DO UPDATE ensures idempotency."""
        now = datetime.now(timezone.utc)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl
        ttl_until = now + timedelta(seconds=ttl)

        async def _upsert(session):
            stmt = (
                pg_insert(VerifiedSecret)
                .values(
                    detector_id=detector_id,
                    secret_hash=secret_hash,
                    verified_at=now,
                    status=status,
                    ttl_until=ttl_until,
                )
                .on_conflict_do_update(
                    constraint="uq_detector_secret",
                    set_={
                        "verified_at": now,
                        "status": status,
                        "ttl_until": ttl_until,
                    },
                )
            )
            await session.execute(stmt)

        run_db(_upsert)

    def invalidate(self, detector_id: str, secret_hash: str) -> None:
        """Force expiry of a cached entry so next scan re-verifies."""
        async def _del(session):
            await session.execute(
                delete(VerifiedSecret).where(
                    VerifiedSecret.detector_id == detector_id,
                    VerifiedSecret.secret_hash == secret_hash,
                )
            )

        run_db(_del)
