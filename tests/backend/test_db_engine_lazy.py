"""Engine + session factory must defer construction until first use.

Without lazy init, any tooling that transitively imports `src.db.engine` (spec
generation, alembic offline ops, isolated unit tests) breaks when
DATABASE_URL is unset. The tests below pin the behaviour: import succeeds
without the env var, but attribute access / get_session / get_sync_url all
fail loudly with an explanatory message.

Each case runs in a fresh subprocess so module-level state (DATABASE_URL,
_engine, _session_factory) cannot leak between tests or pollute the rest of
the suite.
"""
from __future__ import annotations

import subprocess
import sys
import textwrap


def _run(script: str, *, set_database_url: str | None = None) -> subprocess.CompletedProcess:
    """Run a Python snippet in a fresh interpreter with a controlled env."""
    import os

    env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
    if set_database_url is not None:
        env["DATABASE_URL"] = set_database_url
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        env=env,
    )


def test_module_imports_without_database_url():
    result = _run(
        """
        import src.db.engine as e
        assert hasattr(e, "_build_engine")
        assert e.DATABASE_URL == ""
        print("OK")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout


def test_engine_attribute_raises_without_database_url():
    result = _run(
        """
        import src.db.engine as e
        try:
            _ = e.engine
        except RuntimeError as exc:
            msg = str(exc)
            assert "DATABASE_URL" in msg
            print("RAISED")
        else:
            print("NO_RAISE")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "RAISED" in result.stdout


def test_session_factory_attribute_raises_without_database_url():
    result = _run(
        """
        import src.db.engine as e
        try:
            _ = e.async_session_factory
        except RuntimeError as exc:
            assert "DATABASE_URL" in str(exc)
            print("RAISED")
        else:
            print("NO_RAISE")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "RAISED" in result.stdout


def test_get_session_raises_without_database_url():
    result = _run(
        """
        import asyncio
        import src.db.engine as e

        async def main():
            try:
                async with e.get_session() as _s:
                    pass
            except RuntimeError as exc:
                assert "DATABASE_URL" in str(exc)
                print("RAISED")
            else:
                print("NO_RAISE")

        asyncio.run(main())
        """
    )
    assert result.returncode == 0, result.stderr
    assert "RAISED" in result.stdout


def test_get_sync_url_raises_without_database_url():
    result = _run(
        """
        import src.db.engine as e
        try:
            e.get_sync_url()
        except RuntimeError as exc:
            assert "DATABASE_URL" in str(exc)
            print("RAISED")
        else:
            print("NO_RAISE")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "RAISED" in result.stdout


def test_engine_builds_when_database_url_set():
    # asyncpg is already in dependencies; create_async_engine constructs the
    # engine object without attempting a connection.
    result = _run(
        """
        import src.db.engine as e
        engine = e.engine
        factory = e.async_session_factory
        assert engine is not None
        assert factory is not None
        # Calling _build_engine again is idempotent.
        e._build_engine()
        assert e.engine is engine
        assert e.async_session_factory is factory
        print("BUILT")
        """,
        set_database_url="postgresql+asyncpg://u:p@localhost:5432/db",
    )
    assert result.returncode == 0, result.stderr
    assert "BUILT" in result.stdout


def test_get_sync_url_strips_asyncpg_driver():
    result = _run(
        """
        import src.db.engine as e
        assert e.get_sync_url() == "postgresql://u:p@host/db"
        print("OK")
        """,
        set_database_url="postgresql+asyncpg://u:p@host/db",
    )
    assert result.returncode == 0, result.stderr
    assert "OK" in result.stdout
