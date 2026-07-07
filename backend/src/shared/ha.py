"""High-availability primitives backed by Postgres.

When more than one backend instance runs the same lifespan-bound poster, we
need a way to elect exactly one delivery worker at a time so we don't ship
duplicate batches to a SIEM (or duplicate webhook deliveries downstream).

Postgres advisory locks are a good fit: they are session-scoped, non-blocking
when used via ``pg_try_advisory_lock``, and auto-released when the holding
connection dies, so a crashed instance hands the lock off naturally on the
next poll cycle without any manual recovery.

Lock-key convention for new callers
-----------------------------------
Pick a stable ``int64`` from the SHA-256 of a unique ASCII tag::

    int.from_bytes(hashlib.sha256(b"<unique tag>").digest()[:8], "big", signed=True)

The signed=True / first-8-bytes convention is what every advisory-lock caller
in this codebase uses; keeping the same derivation means collisions across
posters require a SHA-256 prefix collision, not just a hash-and-mask clash.
Pick a tag that names what is being guarded (e.g. ``aegis_audit_stream_poster``)
and document the integer alongside the call site so collisions surface during
code review.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL


@asynccontextmanager
async def try_advisory_lock(lock_key: int) -> AsyncIterator[bool]:
    """Try to acquire a Postgres session-scoped advisory lock.

    Yields True if this caller now holds the lock, False if another session
    already holds it. The lock is held for the duration of the ``async with``
    block on a dedicated connection, then released (or auto-released on
    connection close if the body raises and the engine is torn down).

    A fresh engine is built per call so the holding connection is bound to the
    caller's running event loop — asyncpg connections cannot migrate across
    loops, and the audit poster's lifespan task and the test-suite's
    per-test ``asyncio.run`` both create their own loops.
    """
    engine = create_async_engine(DATABASE_URL, echo=False, pool_size=1, max_overflow=0)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    session = factory()
    try:
        acquired = bool(
            (await session.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": lock_key}))
            .scalar()
        )
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    await session.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key})
                    await session.commit()
                except Exception:
                    # Connection teardown below auto-releases; failing the
                    # explicit unlock is non-fatal.
                    await session.rollback()
    finally:
        await session.close()
        await engine.dispose()


@asynccontextmanager
async def advisory_lock(lock_key: int) -> AsyncIterator[None]:
    """Acquire a Postgres session-scoped advisory lock, blocking until granted.

    Unlike :func:`try_advisory_lock`, this waits for the lock instead of
    returning immediately, so callers that must serialize a critical section
    (rather than elect a single owner and skip) will each run the body in turn.
    The lock is held for the duration of the ``async with`` block on a
    dedicated connection, then released.

    A fresh engine is built per call for the same event-loop-affinity reason
    described in :func:`try_advisory_lock`.
    """
    engine = create_async_engine(DATABASE_URL, echo=False, pool_size=1, max_overflow=0)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    session = factory()
    try:
        await session.execute(text("SELECT pg_advisory_lock(:k)"), {"k": lock_key})
        try:
            yield
        finally:
            try:
                await session.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": lock_key})
                await session.commit()
            except Exception:
                # Connection teardown below auto-releases; a failed explicit
                # unlock is non-fatal.
                await session.rollback()
    finally:
        await session.close()
        await engine.dispose()
