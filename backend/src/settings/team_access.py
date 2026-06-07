from __future__ import annotations

from typing import TYPE_CHECKING, Any

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
    from src.settings.router import has_role_permission
    return has_role_permission(user_role, user_role_id, "manage_organisations")

def can_review_repository(user_role: str | None, is_member: bool, user_role_id: str | None = None) -> bool:
    """Checks if a user can review a repository."""
    from src.settings.router import has_role_permission
    if has_role_permission(user_role, user_role_id, "manage_access_scope"):
        return True
    if not is_member:
        return False
    return has_role_permission(user_role, user_role_id, "review_findings")

def user_has_asset_access(
    teams: list[dict[str, Any]],
    user_id: str,
    asset_id: str,
    direct_grants: list[dict[str, Any]] | None = None,
) -> bool:
    # Check direct grants first (faster)
    if direct_grants:
        from src.settings.direct_access_store import user_has_direct_asset_access
        if user_has_direct_asset_access(direct_grants, user_id, asset_id):
            return True

    for team in teams:
        has_member = any(member["userId"] == user_id for member in team.get("members", []))
        has_asset = any(
            item["assetId"] == asset_id
            for item in team.get("assets", [])
        )
        if has_member and has_asset:
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

    for team in teams:
        has_member = any(member["userId"] == user_id for member in team.get("members", []))
        if not has_member:
            continue
        if team.get("assets"):
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
