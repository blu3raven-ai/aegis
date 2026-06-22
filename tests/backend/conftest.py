"""Shared test fixtures — spins up Postgres and MinIO via testcontainers.

Contributors only need Docker installed. Running `pytest` handles everything:
containers start automatically, tables are created, env vars are set,
and containers are torn down when tests finish.
"""
from __future__ import annotations

import os
import sys
import asyncio

# Ensure `backend/` is on sys.path so `from src.X import Y` resolves when
# pytest is invoked from the project root (where backend/pyproject.toml's
# pythonpath = ["."] is not in effect).
_BACKEND_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "backend")
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, os.path.normpath(_BACKEND_DIR))

import pytest


def pytest_configure(config):
    """Set environment variables before ANY module imports.

    This runs before test collection, so src.db.engine (which reads
    DATABASE_URL at import time) sees the testcontainer URL.
    """
    # Provide a test-only SESSION_SECRET so the PR 3 middleware registrations
    # don't raise RuntimeError during import. Must be set before src.main loads.
    os.environ.setdefault("SESSION_SECRET", "test-only-session-secret-not-for-production")
    # TrustedHostMiddleware fails loudly when ALLOWED_HOSTS is unset; the
    # FastAPI TestClient drives requests with Host: testserver by default.
    os.environ.setdefault("ALLOWED_HOSTS", "localhost,127.0.0.1,testserver")

    # Skip testcontainers if DATABASE_URL is already set (e.g., CI with external DB)
    if os.environ.get("DATABASE_URL"):
        return

    from testcontainers.postgres import PostgresContainer

    # Start Postgres — kept alive for the entire test session
    pg = PostgresContainer("postgres:16-alpine", driver="asyncpg")
    pg.start()

    db_url = pg.get_connection_url()
    os.environ["DATABASE_URL"] = db_url

    # Store reference so we can stop it later
    config._pg_container = pg

    # Also set up MinIO if not already configured
    if not os.environ.get("S3_ENDPOINT"):
        try:
            from testcontainers.minio import MinioContainer

            mc = MinioContainer()
            mc.start()
            config._minio_container = mc

            host = mc.get_container_host_ip()
            port = mc.get_exposed_port(9000)
            os.environ["S3_ENDPOINT"] = f"http://{host}:{port}"
            os.environ["S3_ACCESS_KEY"] = "minioadmin"
            os.environ["S3_SECRET_KEY"] = "minioadmin"
            os.environ["S3_BUCKET"] = "scans"
        except ImportError:
            pass


def pytest_unconfigure(config):
    """Stop testcontainers after all tests finish."""
    mc = getattr(config, "_minio_container", None)
    if mc:
        try:
            mc.stop()
        except Exception:
            pass

    pg = getattr(config, "_pg_container", None)
    if pg:
        try:
            pg.stop()
        except Exception:
            pass


@pytest.fixture(scope="session", autouse=True)
def _create_tables():
    """Create all DB tables once per test session."""
    from src.db.engine import engine
    from src.db.models import Base

    async def _setup():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        # Dispose the pool so TestClient requests don't reuse connections that
        # were bound to this (now-closed) event loop. Fresh connections are
        # created per-request in the TestClient's own event loop.
        await engine.dispose()

    asyncio.run(_setup())
    yield
    # No teardown needed — testcontainers destroy the DB container


@pytest.fixture(scope="session", autouse=True)
def _seed_default_roles(_create_tables):
    """Seed the four built-in roles once per test session.

    Required by SessionAuthMiddleware's permission resolution path: when an
    authenticated request arrives, the middleware sets request.state.user_role
    from the session's user.role string (e.g. "owner"), and the permission
    system resolves it via DB lookup. Without seeded roles the lookup raises
    ValueError → empty permissions → 403 on every protected route.

    Individual test files may also seed roles in their own fixtures; that's
    fine — the insert is idempotent (checks for existing before add).
    """
    from datetime import datetime, timezone

    from src.db.helpers import run_db
    from src.db.models import Role
    from src.db.seed import DEFAULT_ROLES

    async def _insert(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data["protected"],
                    created_at=datetime.now(timezone.utc),
                ))

    run_db(_insert)


@pytest.fixture(scope="session", autouse=True)
def _seed_sso_config_singleton(_create_tables):
    """Seed the SSO config singleton row once per test session.

    The production migration seeds this via INSERT, but tests use
    create_all which bypasses migrations, so we mirror it here.
    """
    from src.db.helpers import run_db
    from src.db.models import SsoConfig

    async def _insert(session):
        existing = await session.get(SsoConfig, 1)
        if not existing:
            session.add(SsoConfig(id=1))

    run_db(_insert)


@pytest.fixture(scope="session", autouse=True)
def _seed_scim_config_singleton(_create_tables):
    """Seed the SCIM config singleton row once per test session.

    Mirrors _seed_sso_config_singleton — create_all bypasses migrations so
    the INSERT that normally runs in the alembic upgrade must be reproduced here.
    """
    from src.db.helpers import run_db
    from src.db.models import ScimConfig

    async def _insert(session):
        existing = await session.get(ScimConfig, 1)
        if not existing:
            session.add(ScimConfig(id=1))

    run_db(_insert)


@pytest.fixture(scope="session", autouse=True)
def _seed_audit_stream_config_singleton(_create_tables):
    """Seed the audit-stream config singleton row once per test session.

    Mirrors _seed_scim_config_singleton — create_all bypasses migrations so
    the INSERT that normally runs in the alembic upgrade must be reproduced here.
    """
    from src.db.helpers import run_db
    from src.db.models import AuditStreamConfig

    async def _insert(session):
        existing = await session.get(AuditStreamConfig, 1)
        if not existing:
            session.add(AuditStreamConfig(id=1))

    run_db(_insert)


@pytest.fixture(scope="session")
def db_url():
    """Return the test database URL."""
    return os.environ["DATABASE_URL"]


@pytest.fixture(scope="session")
def s3_endpoint():
    """Return the test MinIO endpoint, or skip if not available."""
    endpoint = os.environ.get("S3_ENDPOINT")
    if not endpoint:
        pytest.skip("MinIO not available")
    return endpoint


def _make_test_session(user_id: str, role: str = "admin") -> str:
    """Create a User + UserSession row in the test DB and return the session ID.

    Called by make_authed_client so tests can exercise routes protected by
    SessionAuthMiddleware without bypassing it.
    """
    from datetime import datetime, timedelta, timezone

    from src.db.helpers import run_db
    from src.db.models import User, UserSession

    session_id = f"test-session-{user_id}"

    async def _insert(session):
        existing_user = await session.get(User, user_id)
        if not existing_user:
            now = datetime.now(timezone.utc)
            # Map slug ("admin") to the seeded role PK ("role_admin") so
            # SessionAuthMiddleware can resolve permissions via role_id FK.
            role_id = f"role_{role}"
            session.add(User(
                id=user_id,
                username=f"test-{user_id}",
                email=f"{user_id}@test.example",
                password_hash="",
                role_id=role_id,
                status="active",
                created_at=now,
                updated_at=now,
            ))

        existing_sess = await session.get(UserSession, session_id)
        if not existing_sess:
            now = datetime.now(timezone.utc)
            session.add(UserSession(
                id=session_id,
                user_id=user_id,
                created_at=now,
                last_seen_at=now,
                expires_at=now + timedelta(hours=8),
                user_agent=None,
                ip_address=None,
            ))

    run_db(_insert)
    return session_id


def make_authed_client(
    role: str = "admin",
    user_id: str | None = None,
    extra_headers: dict | None = None,
    raise_server_exceptions: bool = True,
) -> "TestClient":
    """Return a TestClient with a valid session cookie and CSRF token for the given role.

    Creates a real User + UserSession row so SessionAuthMiddleware passes the
    DB lookup. Sets both the session cookie and CSRF cookie, and includes the
    X-CSRF-Token header by default so mutating requests (POST/PATCH/DELETE)
    pass the CSRFMiddleware check without per-test modification.

    Tests that previously relied on Bearer JWT (require_jwt) use this instead.
    """
    from fastapi.testclient import TestClient
    from src.main import app
    from src.auth.authentication.cookies import SESSION_COOKIE_NAME, CSRF_COOKIE_NAME
    from src.auth.authentication.csrf import compute_csrf_token

    uid = user_id or f"test-usr-{role}"
    session_id = _make_test_session(uid, role=role)

    # Compute the CSRF token so mutating requests pass CSRFMiddleware.
    # Use the hardcoded test secret rather than os.environ: tests such as
    # test_settings.py::test_patch_account_updates_username_and_password call
    # sync_runtime_env_from_config() which permanently overwrites
    # os.environ["SESSION_SECRET"] with a freshly-generated random value,
    # causing CSRF mismatches for all tests that run afterward in the same
    # session. CSRFMiddleware's self.secret is baked in at import time from
    # the value set by pytest_configure (the constant below), so we must use
    # the same constant here.
    secret = "test-only-session-secret-not-for-production"
    csrf_token = compute_csrf_token(session_id, secret=secret)

    cookies = {
        SESSION_COOKIE_NAME: session_id,
        CSRF_COOKIE_NAME: csrf_token,
    }
    headers = {
        # Include by default so POST/PATCH/DELETE tests don't need to add it manually
        "X-CSRF-Token": csrf_token,
        **(extra_headers or {}),
    }
    os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "a" * 64)
    return TestClient(
        app,
        cookies=cookies,
        headers=headers,
        raise_server_exceptions=raise_server_exceptions,
    )
