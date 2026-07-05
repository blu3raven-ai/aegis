"""GraphQL authentication and authorization helpers."""
from __future__ import annotations

from typing import Any

from graphql import GraphQLError

from src.authz.permissions.catalog import VIEW_FINDINGS


async def get_graphql_context(request: Any) -> dict[str, Any]:
    """Extract auth context from FastAPI request state."""
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        raise GraphQLError(
            "Unauthorized",
            extensions={"code": "UNAUTHENTICATED"},
        )

    from src.authz.enforcement import has_permission
    if not has_permission(request, VIEW_FINDINGS):
        raise GraphQLError(
            "Permission denied: view_findings",
            extensions={"code": "PERMISSION_DENIED"},
        )

    role = getattr(request.state, "user_role", None) or "viewer"
    tier = getattr(request.state, "tier", "community")

    from src.db.engine import async_session_factory
    from src.authz.enforcement.scope import get_user_asset_ids
    async with async_session_factory() as db:
        asset_ids = await get_user_asset_ids(db, {"user_id": user_sub, "role": role})

    return {
        "user_id": user_sub,
        "role": role,
        "asset_ids": asset_ids,
        "tier": tier,
        "request": request,
        "_cache": {},
    }


async def get_workspace_context(request: Any) -> dict[str, Any]:
    """Auth context for workspace resolvers — authentication only.

    Unlike get_graphql_context this does NOT enforce VIEW_FINDINGS, which
    lets workspace-admin roles (e.g. a custom role with manage_users but no
    view_findings) reach the workspace surface.
    """
    user_sub = getattr(request.state, "user_sub", None)
    if not user_sub:
        raise GraphQLError(
            "Unauthorized",
            extensions={"code": "UNAUTHENTICATED"},
        )
    role = getattr(request.state, "user_role", None) or "viewer"
    role_id = getattr(request.state, "user_role_id", None)
    tier = getattr(request.state, "tier", "community")
    return {
        "user_id": user_sub,
        "role": role,
        "role_id": role_id,
        "tier": tier,
        "request": request,
    }


def require_admin(ctx: dict[str, Any]) -> None:
    if ctx.get("role") not in ("admin", "owner"):
        raise GraphQLError(
            "Admin role required",
            extensions={"code": "PERMISSION_DENIED"},
        )


def require_enterprise_tier(ctx: dict[str, Any]) -> None:
    if ctx.get("tier") != "enterprise":
        raise GraphQLError(
            "Enterprise tier required for this query",
            extensions={"code": "UPGRADE_REQUIRED"},
        )
