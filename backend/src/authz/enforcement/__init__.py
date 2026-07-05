from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from src.authz.enforcement.dependencies import caller_context
from src.authz.permissions.service import resolve_role_permissions

__all__ = [
    "caller_context",
    "has_permission",
    "require_caller_identity",
    "require_permission",
]


def _resolve_effective_permissions(request: Request) -> set[str]:
    """Resolve the effective permissions for the current request's user role."""
    role_id = getattr(request.state, "user_role_id", None)
    role = getattr(request.state, "user_role", None)

    from src.authz.roles.service import get_role, get_role_by_slug
    try:
        if isinstance(role_id, str) and role_id:
            role_record = get_role(role_id)
        else:
            role_record = get_role_by_slug(str(role))
        return resolve_role_permissions(role_record)
    except ValueError:
        return set()


def has_permission(request: Request, permission: str) -> bool:
    """Check if the current user has a specific permission. Returns bool, does not raise."""
    return permission in _resolve_effective_permissions(request)


def require_permission(request: Request, permission: str) -> None:
    """Check if the current user has a specific permission. Raises 403 if not."""
    if permission not in _resolve_effective_permissions(request):
        raise HTTPException(status_code=403, detail=f"Permission denied: {permission}")


def require_caller_identity(request: Request) -> dict[str, Any]:
    """Resolve the calling identity for endpoints that act on the caller's own account.

    Rejects machine identities (API-key auth never establishes a session) so
    self-service surfaces — TOTP enrollment, email change, avatar — are only
    reachable from interactive human sessions.

    Returns the same context shape as graphql.auth.get_workspace_context so
    resolvers reused by REST handlers receive the expected keys.

    For admin endpoints that need the caller context without the
    interactive-session requirement (e.g. SCIM-paired flows,
    machine-callable admin), use `caller_context` instead.
    """
    if getattr(request.state, "session", None) is None:
        raise HTTPException(
            status_code=403,
            detail="interactive session required",
        )

    if not getattr(request.state, "user_sub", None):
        raise HTTPException(status_code=401, detail="unauthorized")

    return caller_context(request)
