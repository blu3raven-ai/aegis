import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from src.settings import sources_store
from src.settings.sources_store import SourceValidationError


# ── helpers ──────────────────────────────────────────────────────────────────

def _fake_run_db(session):
    """Returns a drop-in for run_db that executes coro_fn synchronously."""
    def fake(coro_fn):
        return asyncio.run(coro_fn(session))
    return fake


def _make_session(existing=None):
    """AsyncSession mock that returns `existing` list from any execute() call."""
    session = AsyncMock()
    scalars = MagicMock()
    scalars.all.return_value = existing or []
    execute_result = MagicMock()
    execute_result.scalars.return_value = scalars
    session.execute = AsyncMock(return_value=execute_result)
    session.add = MagicMock()
    session.flush = AsyncMock()
    return session


def _existing_conn(source_type, org, instance_url=""):
    conn = MagicMock()
    conn.source_type = source_type
    conn.auth = {"orgOrOwner": org}
    if instance_url:
        conn.auth["instanceUrl"] = instance_url
    return conn


# ── duplicate check tests ─────────────────────────────────────────────────────

def test_create_connection_blocks_duplicate_github(monkeypatch):
    existing = _existing_conn("github", "myorg")
    session = _make_session(existing=[existing])
    monkeypatch.setattr(sources_store, "run_db", _fake_run_db(session))

    with pytest.raises(SourceValidationError, match="already exists"):
        sources_store.create_connection({
            "category": "code-repositories",
            "sourceType": "github",
            "name": "My Org",
            "auth": {"orgOrOwner": "myorg", "token": "tok"},
        })


def test_create_connection_case_insensitive_dedup(monkeypatch):
    existing = _existing_conn("github", "MyOrg")
    session = _make_session(existing=[existing])
    monkeypatch.setattr(sources_store, "run_db", _fake_run_db(session))

    with pytest.raises(SourceValidationError, match="already exists"):
        sources_store.create_connection({
            "category": "code-repositories",
            "sourceType": "github",
            "name": "My Org",
            "auth": {"orgOrOwner": "myorg", "token": "tok"},
        })


def test_create_connection_allows_same_org_different_gitlab_instance(monkeypatch):
    existing = _existing_conn("gitlab", "mygroup", instance_url="https://gitlab.example.com")
    session = _make_session(existing=[existing])
    monkeypatch.setattr(sources_store, "run_db", _fake_run_db(session))

    # Different instanceUrl — should be allowed
    result = sources_store.create_connection({
        "category": "code-repositories",
        "sourceType": "gitlab",
        "name": "My Group Other",
        "auth": {
            "orgOrOwner": "mygroup",
            "instanceUrl": "https://gitlab.other.com",
            "token": "tok",
        },
    })
    assert result["sourceType"] == "gitlab"


def test_create_connection_blocks_duplicate_with_instance_url(monkeypatch):
    existing = _existing_conn("gitlab", "mygroup", instance_url="https://gitlab.example.com")
    session = _make_session(existing=[existing])
    monkeypatch.setattr(sources_store, "run_db", _fake_run_db(session))

    with pytest.raises(SourceValidationError, match="already exists"):
        sources_store.create_connection({
            "category": "code-repositories",
            "sourceType": "gitlab",
            "name": "My Group",
            "auth": {
                "orgOrOwner": "mygroup",
                "instanceUrl": "https://gitlab.example.com",
                "token": "tok",
            },
        })


def test_create_connection_no_existing_succeeds(monkeypatch):
    session = _make_session(existing=[])
    monkeypatch.setattr(sources_store, "run_db", _fake_run_db(session))

    result = sources_store.create_connection({
        "category": "code-repositories",
        "sourceType": "github",
        "name": "First Org",
        "auth": {"orgOrOwner": "firstorg", "token": "tok"},
    })
    assert result["sourceType"] == "github"
    assert result["status"] == "not-synced"
