"""Source connections GraphQL resolvers."""
from __future__ import annotations

from typing import Any

from src.graphql.auth import GraphQLAuthError
from src.graphql.types import SourceAuth, SourceConnectionGQL, SourceConnectionsResponse
from src.settings import sources_store
from src.settings.router import has_permission


def source_connections(
    info_context: dict[str, Any],
    category: str | None = None,
) -> SourceConnectionsResponse:
    """Mirror of GET /api/settings/api/sources."""
    if not info_context:
        raise GraphQLAuthError("Unauthorized")

    # Enforce the same view_sources permission as the REST endpoint.
    # Use has_permission (returns bool) rather than require_permission (raises HTTPException)
    # so we can raise a GraphQL-native error instead.
    request = info_context.get("request")
    if request is not None:
        if not has_permission(request, "view_sources"):
            raise GraphQLAuthError("Permission denied: view_sources")

    connections = sources_store.list_connections(category=category)
    return SourceConnectionsResponse(
        connections=[
            SourceConnectionGQL(
                id=str(c.get("id", "")),
                source_type=str(c.get("sourceType", "")),
                category=str(c.get("category", "")),
                name=str(c.get("name", "")),
                status=str(c.get("status", "")),
                auth=SourceAuth(
                    org_or_owner=str(c.get("auth", {}).get("orgOrOwner", ""))
                ),
                last_synced_at=c.get("lastSyncedAt"),
                next_sync_at=c.get("nextSyncAt"),
                sync_schedule=c.get("syncSchedule"),
            )
            for c in connections
        ]
    )
