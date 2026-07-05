"""seed_if_empty must fail loudly when ADMIN_PASSWORD is missing.

Silently logging and returning while creating only an AppConfig row leaves
the DB partially seeded — the next boot sees a non-empty DB, skips seeding
entirely, and the workspace is permanently locked out with no admin user.
The function must raise instead so the operator sets ADMIN_PASSWORD before
retrying. Re-uses the existing testcontainer Postgres via db_session.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import AppConfig, Role, User
from src.db.seed import DEFAULT_ROLES, seed_if_empty


async def _wipe_seed_rows(session) -> None:
    """Remove rows that seed_if_empty might have created.

    The session-level conftest fixtures seed the four built-in roles for the
    rest of the suite; these tests must not leave additional users or
    AppConfig rows behind, and must restore the roles afterwards so unrelated
    tests still see the expected baseline.
    """
    await session.execute(delete(AppConfig).where(AppConfig.id == 1))
    await session.execute(delete(User))
    await session.execute(delete(Role))
    await session.commit()


async def _ensure_empty(session) -> None:
    await _wipe_seed_rows(session)


async def _restore_default_roles(session) -> None:
    from datetime import datetime, timezone

    for role_data in DEFAULT_ROLES:
        existing = await session.get(Role, role_data["id"])
        if existing is None:
            session.add(Role(
                id=role_data["id"],
                name=role_data["name"],
                description=role_data["description"],
                permissions=role_data["permissions"],
                protected=role_data["protected"],
                created_at=datetime.now(timezone.utc),
            ))
    await session.commit()


@pytest_asyncio.fixture
async def empty_db(db_session):
    await _ensure_empty(db_session)
    yield db_session
    await _wipe_seed_rows(db_session)
    await _restore_default_roles(db_session)


@pytest.mark.asyncio
async def test_seed_raises_when_admin_password_unset(empty_db, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD environment variable is required"):
        await seed_if_empty(empty_db)


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
async def test_seed_raises_when_admin_password_whitespace(empty_db, monkeypatch, value):
    monkeypatch.setenv("ADMIN_PASSWORD", value)
    with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
        await seed_if_empty(empty_db)


@pytest.mark.asyncio
async def test_seed_does_not_persist_appconfig_when_failing(empty_db, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    with pytest.raises(RuntimeError):
        await seed_if_empty(empty_db)
    # Force a rollback to emulate the production code path (get_session rolls
    # back on exception) before re-querying.
    await empty_db.rollback()
    config = await empty_db.get(AppConfig, 1)
    assert config is None


@pytest.mark.asyncio
async def test_seed_succeeds_when_admin_password_set(empty_db, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "s3cret-test-password")
    monkeypatch.setenv("ADMIN_USERNAME", "seed-admin")
    monkeypatch.setenv("ADMIN_EMAIL", "seed-admin@example.com")

    await seed_if_empty(empty_db)
    await empty_db.commit()

    admin = (await empty_db.execute(
        select(User).where(User.username == "seed-admin")
    )).scalars().first()
    assert admin is not None
    assert admin.role_id == "role_owner"
    assert admin.email == "seed-admin@example.com"
    assert admin.password_hash.startswith("scrypt:v1:")

    config = await empty_db.get(AppConfig, 1)
    assert config is not None


@pytest.mark.asyncio
async def test_seed_skips_when_db_already_has_user(db_session, monkeypatch):
    """An already-seeded DB short-circuits before touching ADMIN_PASSWORD."""
    from datetime import datetime, timezone
    from uuid import uuid4

    existing = User(
        id=f"existing-{uuid4()}",
        username=f"existing-{uuid4()}",
        email=f"existing+{uuid4()}@example.com",
        password_hash="",
        status="active",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(existing)
    await db_session.commit()

    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    try:
        await seed_if_empty(db_session)  # must not raise
    finally:
        await db_session.execute(delete(User).where(User.id == existing.id))
        await db_session.commit()
