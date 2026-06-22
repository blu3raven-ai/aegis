from __future__ import annotations

from typing import Any


def resolve_role_permissions(role_record: dict[str, Any]) -> set[str]:
    """Resolves all permissions for a role record, including implied ones."""
    role_permissions = role_record.get("permissions", [])
    IMPLIED = {
        # manage_settings → manage_runners keeps backwards-compat for roles
        # provisioned before the runner permission was split out: pre-fix
        # the /api/v1/runners/* admin endpoints all required manage_settings,
        # so anyone with manage_settings already managed runners in
        # practice. The implication preserves that exact behaviour without
        # a data migration, while letting new custom roles grant
        # manage_runners standalone for finer-grained delegation.
        "manage_settings": ["view_settings", "manage_runners"],
        "manage_users": ["view_users"],
        "manage_roles": ["view_roles"],
        "manage_access_scope": ["view_access_scope"],
        "manage_sources": ["view_sources"],
        "export_findings": ["view_findings"],
        "export_reports": ["view_reports"],
    }
    effective_permissions = set(role_permissions)
    for parent, children in IMPLIED.items():
        if parent in effective_permissions:
            effective_permissions.update(children)
    return effective_permissions


def has_role_permission(role: str | None, role_id: str | None, permission: str) -> bool:
    """Check permission from role string/ID without a Request object.

    Used by non-route code (team access predicates, store helpers) that
    doesn't have a Request object but needs to evaluate permissions for a
    given role.
    """
    from src.authz.roles.service import get_role, get_role_by_slug
    try:
        if isinstance(role_id, str) and role_id:
            role_record = get_role(role_id)
        elif role:
            role_record = get_role_by_slug(str(role))
        else:
            return False
        return permission in resolve_role_permissions(role_record)
    except ValueError:
        return False
