"""Shared pytest fixtures and configuration for unit tests.

Most tests mock `run_db` and never touch the real DB, but they still trigger
imports of `src.db.engine`, which raises at module level when `DATABASE_URL`
is unset.

When collected alongside `tests/backend/` (the integration suite), the outer
conftest.py spins up a testcontainer and sets DATABASE_URL first; the
`trylast=True` hook here is a no-op in that case.

For standalone runs (only this directory), we spin up our own testcontainer
so DB-backed tests (test_auth_rate_limit, test_auth_session,
test_auth_login_router) run without manual setup.
"""
from __future__ import annotations

import asyncio
import os
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

_PLACEHOLDER_URL = "postgresql+asyncpg://test:test@localhost:5432/test"


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    existing = os.environ.get("DATABASE_URL", "")
    if existing and existing != _PLACEHOLDER_URL:
        # Outer conftest already provided a real URL — nothing to do.
        os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)
        os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")
        return

    # Standalone run — try to spin up a testcontainer.
    try:
        from testcontainers.postgres import PostgresContainer
        pg = PostgresContainer("postgres:16-alpine", driver="asyncpg")
        pg.start()
        os.environ["DATABASE_URL"] = pg.get_connection_url()
        config._src_tests_pg = pg
    except Exception:
        # Docker unavailable — fall back to placeholder; DB-dependent tests
        # will fail with a connection error.
        os.environ.setdefault("DATABASE_URL", _PLACEHOLDER_URL)

    os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)
    os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")


def pytest_unconfigure(config):
    pg = getattr(config, "_src_tests_pg", None)
    if pg:
        try:
            pg.stop()
        except Exception:
            pass


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    """Create all DB tables once per test session.

    Required for standalone runs where this conftest owns the testcontainer.
    In integrated runs, the outer conftest's _create_tables runs first;
    create_all is idempotent so running it again is safe.
    """
    from src.db.engine import DATABASE_URL as _url
    if _url == _PLACEHOLDER_URL:
        yield
        return

    _engine = create_async_engine(_url, echo=False)

    async def _setup():
        from src.db.models import Base
        async with _engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _engine.dispose()

    asyncio.run(_setup())
    yield


@pytest_asyncio.fixture
async def db_session():
    """Yield a real AsyncSession for each test.

    Creates a fresh engine per test so the asyncpg connection is always bound
    to the current test's event loop — avoids 'connection belongs to a
    different loop' errors when pytest-asyncio creates a new loop per test.
    Rows are deleted via an explicit DELETE at teardown rather than rollback,
    because SessionService commits mid-test (rollback after commit is a no-op
    in SQLAlchemy's autobegin model).
    """
    from src.db.engine import DATABASE_URL
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture
async def seed_user(db_session):
    """Insert a minimal User row; deleted at teardown."""
    from src.db.models import User

    user = User(
        id=f"test-{uuid4()}",
        username=f"testuser-{uuid4()}",
        email=f"test+{uuid4()}@example.com",
        password_hash="",
        status="active",
    )
    db_session.add(user)
    await db_session.commit()
    yield user
    # Clean up sessions and the user row created by this fixture
    from sqlalchemy import delete
    from src.db.models import UserSession
    await db_session.execute(delete(UserSession).where(UserSession.user_id == user.id))
    await db_session.execute(delete(User).where(User.id == user.id))
    await db_session.commit()
