"""GraphQL authentication and authorization helpers."""
from __future__ import annotations

from typing import Any

from src.shared.config import get_orgs_from_source_connections


class GraphQLAuthError(Exception):
    """Raised when GraphQL auth check fails."""


def get_graphql_context(request: Any) -> dict[str, Any]:
    """Extract auth context from FastAPI request state."""
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        raise GraphQLAuthError("Unauthorized")

    # Enforce view_findings permission for all GraphQL queries
    from src.settings.router import has_permission
    if not has_permission(request, "view_findings"):
        raise GraphQLAuthError("Permission denied: view_findings")

    role = getattr(request.state, "user_role", None) or "viewer"
    tier = getattr(request.state, "tier", "community")

    # Resolve org scope — get all orgs from source connections
    orgs = get_orgs_from_source_connections()

    return {
        "user_id": user_sub,
        "role": role,
        "orgs": orgs,
        "tier": tier,
        "request": request,
        "_cache": {},  # per-request cache to avoid N+1 resolver reads
    }


def validate_org_access(ctx: dict[str, Any], org: str) -> None:
    """Ensure user has access to the requested org."""
    user_orgs = ctx.get("orgs", [])
    if org not in user_orgs:
        raise GraphQLAuthError(f"Access denied to org '{org}'")


def require_admin(ctx: dict[str, Any]) -> None:
    """Ensure user has admin or owner role."""
    if ctx.get("role") not in ("admin", "owner"):
        raise GraphQLAuthError("Admin role required")


def require_pro_tier(ctx: dict[str, Any]) -> None:
    """Ensure workspace is on Pro or Enterprise tier."""
    if ctx.get("tier") == "community":
        raise GraphQLAuthError("Pro tier required for this query")
