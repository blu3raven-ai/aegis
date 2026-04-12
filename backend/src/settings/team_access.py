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
def user_has_repository_access(
    teams: list[dict[str, Any]], 
    user_id: str, 
    org: str, 
    repo: str,
    direct_grants: list[dict[str, Any]] | None = None
) -> bool:
    org_key = org.lower()
    repo_key = repo.lower()
    
    # Check direct grants first (faster)
    if direct_grants:
        from src.settings.direct_access_store import user_has_direct_repository_access
        if user_has_direct_repository_access(direct_grants, user_id, org, repo):
            return True

    for team in teams:
        has_member = any(member["userId"] == user_id for member in team.get("members", []))
        has_repo = any(
            item["org"].lower() == org_key and item["repo"].lower() == repo_key
            for item in team.get("repositories", [])
        )
        if has_member and has_repo:
            return True
    return False

def user_has_container_image_access(
    teams: list[dict[str, Any]], 
    user_id: str, 
    image: str,
    direct_grants: list[dict[str, Any]] | None = None
) -> bool:
    image_key = image.strip().lower()
    
    # Check direct grants first
    if direct_grants:
        for grant in direct_grants:
            if (
                grant.get("userId") == user_id
                and grant.get("resourceType") == "containerImage"
                and grant.get("resourceKey", "").lower() == image_key
            ):
                return True

    for team in teams:
        has_member = any(member["userId"] == user_id for member in team.get("members", []))
        has_image = any(
            item.get("image", "").lower() == image_key
            for item in team.get("containerImages", [])
        )
        if has_member and has_image:
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
        if team.get("repositories") or team.get("containerImages"):
            return True
    return False

def get_effective_team_role_for_repository(teams: list[dict[str, Any]], user_id: str, org: str, repo: str) -> str | None:
    """
    Legacy helper being migrated. Returns None as team roles are no longer authoritative.
    """
    return None
