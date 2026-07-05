"""Declarative `Depends()`-style permission enforcement.

`Permission(PERM)` is the declarative counterpart to
`require_permission(request, PERM)`: same PDP, same 403 on deny, but
expressed in the route signature so the auth requirement is visible in
the function signature and in the generated OpenAPI schema.

Equality semantics: two `Permission` instances built from the same set
of permissions hash and compare equal, so a test that does

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None

overrides every route declared with `Depends(Permission(MANAGE_SETTINGS))`
even when the override and the route construct separate instances.
"""
from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from src.authz.permissions.service import has_role_permission


class Permission:
    """Permission guard usable as a FastAPI dependency.

    `Permission(A, B)` requires *all* listed permissions (AND semantics).
    For OR semantics, write a small custom guard at the call site.
    """

    __slots__ = ("_permissions",)

    def __init__(self, *permissions: str) -> None:
        if not permissions:
            raise ValueError("Permission requires at least one permission name")
        self._permissions: tuple[str, ...] = tuple(permissions)

    def __call__(self, request: Request) -> None:
        role = getattr(request.state, "user_role", None)
        role_id = getattr(request.state, "user_role_id", None)
        for permission in self._permissions:
            if not has_role_permission(role, role_id, permission):
                raise HTTPException(
                    status_code=403,
                    detail=f"Permission denied: {permission}",
                )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Permission):
            return NotImplemented
        return self._permissions == other._permissions

    def __hash__(self) -> int:
        return hash(self._permissions)

    def __repr__(self) -> str:
        return f"Permission({', '.join(self._permissions)})"


def caller_context(request: Request) -> dict[str, Any]:
    """Build the info_context dict shared by REST handlers that delegate
    to workspace / runner service functions.

    Mirrors the shape of graphql.auth.get_workspace_context (keys:
    user_id, role, role_id, tier, request) so the shared service helpers
    receive the same keys whether called from REST or GraphQL.

    Unlike `require_caller_identity`, this dependency does NOT enforce
    an interactive session — it is safe to compose with `Permission(...)`
    on admin endpoints that must also be reachable by machine identities.
    """
    return {
        "user_id": getattr(request.state, "user_sub", None),
        "role": getattr(request.state, "user_role", None) or "viewer",
        "role_id": getattr(request.state, "user_role_id", None),
        "tier": getattr(request.state, "tier", "community"),
        "request": request,
    }
