"""Unit tests for the source connections GraphQL resolver."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from src.graphql.auth import GraphQLAuthError
from src.graphql.types import SourceConnectionsResponse, SourceConnectionGQL


def _make_request(has_view_sources: bool = True):
    """Minimal fake request object for permission checks."""
    class FakeState:
        user_role = "admin" if has_view_sources else "viewer"
        user_role_id = "role_admin" if has_view_sources else "role_viewer"

    class FakeRequest:
        state = FakeState()

    return FakeRequest()


def _ctx(has_view_sources: bool = True) -> dict:
    return {
        "user_id": "u1",
        "role": "admin" if has_view_sources else "viewer",
        "orgs": ["acme-org"],
        "tier": "pro",
        "request": _make_request(has_view_sources),
        "_cache": {},
    }


def _make_connection(conn_id: str, category: str = "code-repositories") -> dict:
    return {
        "id": conn_id,
        "sourceType": "github",
        "category": category,
        "name": f"Connection {conn_id}",
        "status": "connected",
        "auth": {"orgOrOwner": "acme-org"},
        "lastSyncedAt": "2024-01-01T00:00:00Z",
        "nextSyncAt": "2024-01-02T00:00:00Z",
        "syncSchedule": "6h",
    }


def test_source_connections_returns_list():
    """Resolver returns a SourceConnectionsResponse with all connections from the store."""
    from src.graphql.sources_resolvers import source_connections

    raw = [
        _make_connection("src_aaa", "code-repositories"),
        _make_connection("src_bbb", "container-images"),
    ]

    with patch("src.graphql.sources_resolvers.sources_store.list_connections", return_value=raw), \
         patch("src.graphql.sources_resolvers.has_permission", return_value=True):
        result = source_connections(info_context=_ctx(), category=None)

    assert isinstance(result, SourceConnectionsResponse)
    assert len(result.connections) == 2
    ids = {c.id for c in result.connections}
    assert ids == {"src_aaa", "src_bbb"}
    first = result.connections[0]
    assert isinstance(first, SourceConnectionGQL)
    assert first.auth.org_or_owner == "acme-org"


def test_source_connections_filters_by_category():
    """Resolver passes the category filter through to the store."""
    from src.graphql.sources_resolvers import source_connections

    raw = [_make_connection("src_ccc", "code-repositories")]

    with patch("src.graphql.sources_resolvers.sources_store.list_connections", return_value=raw) as mock_list, \
         patch("src.graphql.sources_resolvers.has_permission", return_value=True):
        result = source_connections(info_context=_ctx(), category="code-repositories")

    mock_list.assert_called_once_with(category="code-repositories")
    assert len(result.connections) == 1
    assert result.connections[0].category == "code-repositories"


def test_source_connections_requires_view_sources_permission():
    """Resolver raises GraphQLAuthError when the caller lacks view_sources permission."""
    from src.graphql.sources_resolvers import source_connections

    with patch("src.graphql.sources_resolvers.has_permission", return_value=False):
        with pytest.raises(GraphQLAuthError, match="view_sources"):
            source_connections(info_context=_ctx(has_view_sources=False))


def test_source_connections_raises_when_no_context():
    """Resolver raises GraphQLAuthError when info_context is None/empty."""
    from src.graphql.sources_resolvers import source_connections

    with pytest.raises(GraphQLAuthError):
        source_connections(info_context=None)  # type: ignore[arg-type]


def test_source_connections_maps_fields():
    """Resolver correctly maps all exposed fields from the store dict."""
    from src.graphql.sources_resolvers import source_connections

    raw = [
        {
            "id": "src_xyz",
            "sourceType": "gitlab",
            "category": "code-repositories",
            "name": "My GitLab",
            "status": "not-synced",
            "auth": {"orgOrOwner": "example-org"},
            "lastSyncedAt": None,
            "nextSyncAt": None,
            "syncSchedule": "12h",
        }
    ]

    with patch("src.graphql.sources_resolvers.sources_store.list_connections", return_value=raw), \
         patch("src.graphql.sources_resolvers.has_permission", return_value=True):
        result = source_connections(info_context=_ctx())

    conn = result.connections[0]
    assert conn.id == "src_xyz"
    assert conn.source_type == "gitlab"
    assert conn.category == "code-repositories"
    assert conn.name == "My GitLab"
    assert conn.status == "not-synced"
    assert conn.auth.org_or_owner == "example-org"
    assert conn.last_synced_at is None
    assert conn.sync_schedule == "12h"
