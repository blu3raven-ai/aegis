"""Helpers for running async DB operations from synchronous store functions."""
from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable, Coroutine, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.db.engine import DATABASE_URL

T = TypeVar("T")

# Dedicated event loop running in a background thread for sync callers.
# This avoids deadlocks with FastAPI's main loop and keeps asyncpg connections
# on a single consistent loop.
_loop: asyncio.AbstractEventLoop | None = None
_loop_lock = threading.Lock()
_session_factory: async_sessionmaker[AsyncSession] | None = None


def _get_loop_and_factory() -> tuple[asyncio.AbstractEventLoop, async_sessionmaker[AsyncSession]]:
    global _loop, _session_factory
    if _loop is not None and _session_factory is not None:
        return _loop, _session_factory
    with _loop_lock:
        if _loop is not None and _session_factory is not None:
            return _loop, _session_factory
        _loop = asyncio.new_event_loop()
        engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
        _session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        t = threading.Thread(target=_loop.run_forever, daemon=True)
        t.start()
        return _loop, _session_factory


def run_db(coro_fn: Callable[[AsyncSession], Coroutine[Any, Any, T]]) -> T:
    """Run an async DB operation from synchronous code.

    Uses a dedicated background event loop with its own engine/connection pool.
    This avoids deadlocking with FastAPI's main loop and keeps asyncpg
    connections bound to a single consistent loop.
    """
    loop, factory = _get_loop_and_factory()

    async def _run() -> T:
        async with factory() as session:
            try:
                result = await coro_fn(session)
                await session.commit()
                return result
            except Exception:
                await session.rollback()
                raise

    future = asyncio.run_coroutine_threadsafe(_run(), loop)
    return future.result()
