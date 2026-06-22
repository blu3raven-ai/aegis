"""Source connections record how they were connected (pat / webhook / cicd)."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest  # noqa: E402

from src.sources import store as sources_store  # noqa: E402
from src.sources.store import SourceValidationError  # noqa: E402


def _create(methods=None, org="acme-methods-org"):
    data = {
        "category": "code-repositories",
        "sourceType": "github",
        "name": "methods-test",
        "auth": {"orgOrOwner": org, "token": "t"},
    }
    if methods is not None:
        data["connectionMethods"] = methods
    return sources_store.create_connection(data)


def test_defaults_to_pat_when_unspecified():
    conn = _create(org="acme-methods-default-org")
    assert conn["connectionMethods"] == ["pat"]


def test_records_explicit_method():
    conn = _create(methods=["webhook"], org="acme-methods-webhook-org")
    assert conn["connectionMethods"] == ["webhook"]


def test_records_method_combination():
    conn = _create(methods=["pat", "webhook"], org="acme-methods-combo-org")
    assert conn["connectionMethods"] == ["pat", "webhook"]


def test_rejects_unknown_method():
    with pytest.raises(SourceValidationError):
        _create(methods=["ftp"], org="acme-methods-bad-org")


def test_empty_method_list_falls_back_to_pat():
    # An omitted or empty selection means the default token connection.
    conn = _create(methods=[], org="acme-methods-empty-org")
    assert conn["connectionMethods"] == ["pat"]
