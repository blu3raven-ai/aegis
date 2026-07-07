"""Regression tests for the startup-migration advisory lock.

The server runs multiple worker processes, each of which executes the app
lifespan and its ``alembic upgrade head`` step. Without serialization, two
workers migrating a fresh database race on DDL (e.g. duplicate ``CREATE TYPE``)
and one crashes. A blocking Postgres advisory lock makes the second worker wait
for the first to finish, then run the migration as a no-op.

These tests pin the lock-key constant and exercise the real blocking semantics
against Postgres so the guarantee is not a mock.
"""
from __future__ import annotations

import asyncio
import hashlib
import os

os.environ.setdefault("APP_SECRET", "0" * 64)
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

import pytest  # noqa: E402

from src import main  # noqa: E402
from src.shared.ha import advisory_lock  # noqa: E402


def test_migration_lock_key_constant_is_stable():
    """Pin the int64 derivation so a refactor of the constant surfaces here.

    Every worker must derive the same key or the serialization is defeated —
    two workers on different keys would both migrate concurrently and race.
    """
    expected = int.from_bytes(
        hashlib.sha256(b"aegis_schema_migration").digest()[:8],
        "big",
        signed=True,
    )
    assert main._MIGRATION_ADVISORY_LOCK_KEY == expected
    assert main._MIGRATION_ADVISORY_LOCK_KEY == 1587967693441817285


def test_migration_runs_inside_advisory_lock():
    """The alembic upgrade must live inside the advisory-lock context.

    A source-level check is cheap insurance against someone moving the
    ``subprocess.run`` call back outside the ``async with advisory_lock(...)``
    block and silently reintroducing the worker race.
    """
    import inspect

    src = inspect.getsource(main.lifespan)
    lock_at = src.find("async with advisory_lock(")
    alembic_at = src.find('subprocess.run(["alembic"')
    assert lock_at != -1, "advisory_lock context not found in lifespan"
    assert alembic_at != -1, "alembic upgrade call not found in lifespan"
    assert lock_at < alembic_at, "alembic upgrade must run inside the advisory lock"


@pytest.mark.asyncio
async def test_advisory_lock_blocks_until_released():
    """A second acquirer must block while the first holds the same key.

    This is the property that fixes the migration race: the losing worker
    waits rather than proceeding to migrate/serve against an unmigrated schema.
    """
    key = main._MIGRATION_ADVISORY_LOCK_KEY
    second_acquired = asyncio.Event()

    async def _second_waiter() -> None:
        async with advisory_lock(key):
            second_acquired.set()

    async with advisory_lock(key):
        waiter = asyncio.create_task(_second_waiter())
        # While we hold the lock the waiter blocks in pg_advisory_lock and
        # must not acquire, even given time to run.
        await asyncio.sleep(1.0)
        assert not second_acquired.is_set()

    # Lock released — the waiter now proceeds.
    await asyncio.wait_for(waiter, timeout=5.0)
    assert second_acquired.is_set()
