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

    asyncio.run(_setup())
    yield
    # No teardown needed — testcontainers destroy the DB container


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
