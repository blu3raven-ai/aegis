"""Tests for Phase 0 cache schema migration.

Uses a dedicated Postgres container (separate from the session-wide one in
conftest.py) so that Alembic migrations are run rather than create_all.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text


BACKEND_DIR = Path(__file__).parent.parent.parent / "backend"


@pytest.fixture(scope="module")
def db_engine():
    """Start a fresh Postgres container, run alembic upgrade head, yield engine.

    DATABASE_URL must carry the asyncpg scheme because src.db.engine imports at
    module level and calls create_async_engine().  Alembic's env.py then strips
    '+asyncpg' to get a psycopg2-compatible URL for the sync migration runner.
    """
    from testcontainers.postgres import PostgresContainer

    # driver=None → plain postgresql:// URL; we'll add +asyncpg ourselves
    with PostgresContainer("postgres:16-alpine", driver=None) as pg:
        base_url = pg.get_connection_url()  # postgresql://user:pass@host:port/db

        # asyncpg URL for DATABASE_URL (required by src.db.engine module import)
        asyncpg_url = base_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        env = {**os.environ, "DATABASE_URL": asyncpg_url}
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(BACKEND_DIR),
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"alembic upgrade head failed:\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

        # Use plain psycopg2 URL for synchronous SQLAlchemy inspection
        sync_url = base_url.replace("postgresql://", "postgresql+psycopg2://", 1)
        engine = create_engine(sync_url)
        yield engine
        engine.dispose()


def test_cache_entries_table_exists(db_engine):
    insp = inspect(db_engine)
    assert "cache_entries" in insp.get_table_names()
    cols = {c["name"] for c in insp.get_columns("cache_entries")}
    expected = {"cache_type", "cache_key", "content_hash", "tool_version",
                "rule_pack_version", "created_at", "last_used_at", "blob_pointer"}
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"


def test_verified_secrets_table_exists(db_engine):
    insp = inspect(db_engine)
    assert "verified_secrets" in insp.get_table_names()
    cols = {c["name"] for c in insp.get_columns("verified_secrets")}
    expected = {"detector_id", "secret_hash", "verified_at", "status", "ttl_until"}
    assert expected.issubset(cols), f"Missing columns: {expected - cols}"


def test_repos_table_gained_delta_columns(db_engine):
    """The repos table is created fresh by this migration (it did not exist in
    the initial schema) and must carry the delta-detection columns."""
    insp = inspect(db_engine)
    table_name = "repos"
    assert table_name in insp.get_table_names(), f"Table {table_name} not found"
    cols = {c["name"] for c in insp.get_columns(table_name)}
    assert "manifest_set_hash" in cols
    assert "last_scanned_sha" in cols


def test_findings_has_commit_attribution_columns(db_engine):
    """Migration b3c4d5e6f7a8 added four attribution columns to findings."""
    insp = inspect(db_engine)
    assert "findings" in insp.get_table_names()
    cols = {c["name"] for c in insp.get_columns("findings")}
    expected = {
        "introduced_by_commit_sha",
        "introduced_by_author",
        "introduced_at",
        "introduced_by_pr_url",
    }
    assert expected.issubset(cols), f"Missing attribution columns: {expected - cols}"
