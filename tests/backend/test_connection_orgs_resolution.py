"""Tests for `_connection_orgs` — the org set a connection's scan runs match on.

Regression guard: cherry-pick / multi-org PAT connections carry no single
`orgOrOwner`, so their active scan runs must still resolve back to the
connection (via discovered repo prefixes) or the progress banner never appears.
"""
from __future__ import annotations

from src.sources.source_connections_router import _connection_orgs


def test_explicit_org_or_owner_wins() -> None:
    conn = {"auth": {"orgOrOwner": "Acme-Org"}, "discoveredItems": ["other/repo"]}
    assert _connection_orgs(conn) == {"acme-org"}


def test_derives_orgs_from_discovered_repos_when_no_org() -> None:
    conn = {
        "auth": {"token": "x"},  # no orgOrOwner
        "discoveredItems": ["acme-org/a", "acme-org/b", "Other-Org/c"],
    }
    assert _connection_orgs(conn) == {"acme-org", "other-org"}


def test_ignores_malformed_discovered_items() -> None:
    conn = {"auth": {}, "discoveredItems": ["no-slash", "", 123, "acme-org/repo"]}
    assert _connection_orgs(conn) == {"acme-org"}


def test_empty_when_nothing_to_derive() -> None:
    assert _connection_orgs({"auth": {}, "discoveredItems": []}) == set()
    assert _connection_orgs({}) == set()
