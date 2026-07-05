"""verify_api_key must run natively async — never block the event loop.

Regression test for TODO #15. The previous implementation called run_db()
which used Future.result() on a sync DB session; that froze the calling
coroutine on each authenticated request and serialized concurrent traffic.

These tests simulate a slow DB read and assert that N parallel lookups
complete in roughly the time of one (proving concurrency), and that an
interleaving coroutine actually gets CPU time while the lookup is in flight.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.auth.credentials.auth import verify_api_key  # noqa: E402

_TOKEN = "ak_live_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_PER_CALL_SLEEP = 0.05  # 50 ms simulated DB latency


def _matching_row() -> SimpleNamespace:
    token_hash = hashlib.sha256(_TOKEN.encode()).hexdigest()
    return SimpleNamespace(
        id=1,
        token_hash=token_hash,
        revoked_at=None,
        expires_at=None,
        scopes=["scan:trigger"],
        allowed_source_ids=None,
    )


class _SlowSession:
    """Async context manager whose .execute() awaits asyncio.sleep().

    Sleeping in async (not time.sleep) is the whole point — if the lookup
    is implemented with a thread-pool/.result() bridge the sleep blocks
    the thread, not the event loop, and the test still passes. Here we
    sleep inside the coroutine returned by session.execute() so only an
    event-loop-friendly caller can interleave with peers.
    """

    def __init__(self, row):
        self._row = row

    async def __aenter__(self):
        async def _execute(*_args, **_kwargs):
            await asyncio.sleep(_PER_CALL_SLEEP)
            scalars = MagicMock()
            scalars.first.return_value = self._row
            result = MagicMock()
            result.scalar_one_or_none.return_value = self._row
            result.scalars.return_value = scalars
            return result

        session = MagicMock()
        session.execute = _execute
        return session

    async def __aexit__(self, *_args):
        return None


@pytest.mark.asyncio
async def test_verify_api_key_runs_concurrently():
    """N parallel verifications complete in roughly the time of one.

    If verify_api_key blocks the event loop, total wall time would be
    N * _PER_CALL_SLEEP. With native async, it should be ~_PER_CALL_SLEEP.
    """
    row = _matching_row()
    n = 8

    def _new_session(*_a, **_kw):
        return _SlowSession(row)

    with patch("src.db.engine.get_session", side_effect=_new_session):
        start = time.monotonic()
        results = await asyncio.gather(
            *[verify_api_key(f"Bearer {_TOKEN}") for _ in range(n)]
        )
        elapsed = time.monotonic() - start

    assert all(r is not None for r in results)
    # The proof of concurrency is finishing well under the serial time
    # (n * 0.05 = 0.4s). Bound at 0.75x (0.3s) so serialization still fails loudly
    # while leaving headroom for event-loop scheduling jitter on slow/loaded CI
    # runners — a tighter 0.5x (0.2s) bound flakes there despite true concurrency.
    assert elapsed < (n * _PER_CALL_SLEEP) * 0.75, (
        f"verify_api_key serialized — {n} calls took {elapsed:.3f}s, "
        f"expected < {(n * _PER_CALL_SLEEP) * 0.75:.3f}s"
    )


@pytest.mark.asyncio
async def test_verify_api_key_yields_to_other_coroutines():
    """A peer coroutine ticks while verify_api_key is awaiting DB."""
    row = _matching_row()
    ticks: list[float] = []

    async def _ticker():
        # Should accumulate ticks throughout the lookup if the loop is free.
        for _ in range(10):
            ticks.append(time.monotonic())
            await asyncio.sleep(0.005)

    def _new_session(*_a, **_kw):
        return _SlowSession(row)

    with patch("src.db.engine.get_session", side_effect=_new_session):
        await asyncio.gather(
            verify_api_key(f"Bearer {_TOKEN}"),
            _ticker(),
        )

    # Spread of ticks across the lookup window proves the loop never stalled.
    assert len(ticks) == 10
    spread = ticks[-1] - ticks[0]
    assert spread >= 0.02, f"event loop appears blocked — tick spread was {spread:.4f}s"


@pytest.mark.asyncio
async def test_verify_api_key_rejects_bad_prefix():
    result = await verify_api_key("Bearer not_a_real_token")
    assert result is None


@pytest.mark.asyncio
async def test_verify_api_key_rejects_revoked():
    row = _matching_row()
    row.revoked_at = datetime.now(timezone.utc)

    def _new_session(*_a, **_kw):
        return _SlowSession(row)

    with patch("src.db.engine.get_session", side_effect=_new_session):
        result = await verify_api_key(f"Bearer {_TOKEN}")

    assert result is None
