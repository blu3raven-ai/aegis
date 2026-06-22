from __future__ import annotations

from typing import TYPE_CHECKING, Any

from src.authz.permissions.catalog import MANAGE_ACCESS_SCOPE, MANAGE_ORGANISATIONS, REVIEW_FINDINGS

if TYPE_CHECKING:
    from fastapi import Request

def actor_user_id(request: Request) -> str:
    """Extracts the user ID from the request state."""
    return str(getattr(request.state, "user_sub", "") or "")

def actor_global_role(request: Request) -> str | None:
    """Extracts the global user role from the request state."""
    return getattr(request.state, "user_role", None)

def can_manage_team(user_role: str | None, user_role_id: str | None = None) -> bool:
    """Checks if a user can manage a team via the manage_organisations permission."""
    from src.authz.permissions.service import has_role_permission
    return has_role_permission(user_role, user_role_id, MANAGE_ORGANISATIONS)

def can_review_repository(user_role: str | None, is_member: bool, user_role_id: str | None = None) -> bool:
    """Checks if a user can review a repository."""
    from src.authz.permissions.service import has_role_permission
    if has_role_permission(user_role, user_role_id, MANAGE_ACCESS_SCOPE):
        return True
    if not is_member:
        return False
    return has_role_permission(user_role, user_role_id, REVIEW_FINDINGS)

def user_has_asset_access(
    teams: list[dict[str, Any]],
    user_id: str,
    asset_id: str,
    direct_grants: list[dict[str, Any]] | None = None,
) -> bool:
    # Check direct user grants
    if direct_grants:
        if any(g.get("userId") == user_id and g.get("assetId") == asset_id for g in direct_grants):
            return True
    return False

def user_has_any_scoped_access(
    teams: list[dict[str, Any]],
    user_id: str,
    direct_grants: list[dict[str, Any]] | None = None
) -> bool:
    if direct_grants:
        if any(g.get("userId") == user_id for g in direct_grants):
            return True
    return False

def user_has_repository_access(
    teams: list[dict[str, Any]],
    user_id: str,
    org: str,
    repo: str,
    direct_grants: list[dict[str, Any]] | None = None,
) -> bool:
    # Callers that only have (org, repo) and not asset_id cannot perform
    # asset-level grant checks. Always returns False until those callers are
    # migrated (Task 3) to pass asset_id.
    return False


def user_has_container_image_access(
    teams: list[dict[str, Any]],
    user_id: str,
    image: str,
    direct_grants: list[dict[str, Any]] | None = None,
) -> bool:
    # Same as user_has_repository_access — pending Task 3 migration.
    return False


def get_effective_team_role_for_repository(teams: list[dict[str, Any]], user_id: str, org: str, repo: str) -> str | None:
    """
    Legacy helper being migrated. Returns None as team roles are no longer authoritative.
    """
    return None
