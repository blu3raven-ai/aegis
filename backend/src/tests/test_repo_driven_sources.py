"""Store-layer tests for repo-driven (cherry-pick) source connections."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.sources import store  # noqa: E402


def test_create_selected_connection_persists_included_items():
    conn = store.create_connection({
        "category": "code-repositories",
        "sourceType": "github",
        "name": "Cherry-picked",
        "auth": {"token": "ghp_x"},
        "scanScope": "selected",
        "includedItems": ["acme/api", "beta/payments"],
        "connectionMethods": ["pat"],
    })
    assert conn["scanScope"] == "selected"
    assert conn["includedItems"] == ["acme/api", "beta/payments"]


def test_blank_org_connections_do_not_collide():
    store.create_connection({
        "category": "code-repositories", "sourceType": "github",
        "name": "A", "auth": {"token": "ghp_a"},
        "scanScope": "selected", "includedItems": ["acme/api"],
    })
    store.create_connection({
        "category": "code-repositories", "sourceType": "github",
        "name": "B", "auth": {"token": "ghp_b"},
        "scanScope": "selected", "includedItems": ["beta/web"],
    })  # must NOT raise SourceValidationError
