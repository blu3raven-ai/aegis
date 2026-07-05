"""SQLAlchemy async engine and session factory."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

DATABASE_URL = os.environ.get("DATABASE_URL", "")

_engine = None
_session_factory = None


def _build_engine() -> None:
    global _engine, _session_factory
    if _engine is not None:
        return
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL environment variable is required. "
            "Set it in the environment before constructing the engine or opening a session."
        )
    _engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
    _session_factory = async_sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


def __getattr__(name: str):
    # PEP 562: defer engine + factory construction until first attribute access
    # so tooling can import this module without DATABASE_URL when it doesn't
    # actually need a live connection (spec generation, alembic offline ops,
    # isolated unit tests).
    if name == "engine":
        _build_engine()
        return _engine
    if name == "async_session_factory":
        _build_engine()
        return _session_factory
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@asynccontextmanager
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    _build_engine()
    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_sync_url() -> str:
    """Return a synchronous DB URL for Alembic (replaces asyncpg with psycopg2)."""
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is required")
    return DATABASE_URL.replace("+asyncpg", "")
