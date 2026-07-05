"""Shared router helpers used across all scanning tool API routers.

Contains org parsing dependency, scope filtering, and error responses.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.authz.teams.access import actor_user_id, user_has_repository_access
from src.authz.enforcement import has_permission
from src.authz.teams.service import list_teams
from src.authz.permissions.catalog import MANAGE_ACCESS_SCOPE
from src.authz.teams.direct_access import list_direct_grants
from src.shared.paths import parse_org_values


def require_orgs(org: list[str] = Query(default_factory=list)) -> list[str]:
    """FastAPI dependency that parses and validates the org query parameter.

    Usage: `orgs: list[str] = Depends(require_orgs)`
    """
    orgs = parse_org_values(org)
    if not orgs:
        raise HTTPException(status_code=400, detail="Missing org parameter")
    return orgs


def filter_by_user_scope(
    request: Request,
    items: list[dict[str, Any]],
    org_key: str = "organization",
    repo_key: str = "repository",
) -> list[dict[str, Any]]:
    """Filter items by user's repository access scope.

    Workspace admins see everything. Other users only see items
    for repositories they have access to via team membership or direct grants.
    """
    if has_permission(request, MANAGE_ACCESS_SCOPE):
        return items
    user_id = actor_user_id(request)
    teams = list_teams()
    direct_grants = list_direct_grants()
    return [
        item for item in items
        if user_has_repository_access(
            teams, user_id,
            str(item.get(org_key) or ""),
            str(item.get(repo_key) or ""),
            direct_grants=direct_grants,
        )
    ]


def validate_org(org: str) -> None:
    """Validate that the org exists in source connections. Raises 403 if not."""
    from src.shared.config import get_orgs_from_source_connections
    valid_orgs = get_orgs_from_source_connections()
    if org not in valid_orgs:
        raise HTTPException(status_code=403, detail="Access denied to org")


def api_error(message: str, status_code: int) -> JSONResponse:
    """Return a JSON error response."""
    return JSONResponse({"error": message}, status_code=status_code)
