from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Role
from src.shared.paths import now_iso as _now_iso
from src.shared.ttl_cache import TtlCache

_role_cache = TtlCache(ttl_seconds=60)

BUILTIN_PERMISSION_IDS = {
    "view_dashboards",
    "view_findings",
    "review_findings",
    "export_findings",
    "run_scans",
    "cancel_scans",
    "view_scan_history",
    "view_reports",
    "export_reports",
    "view_settings",
    "manage_settings",
    "view_users",
    "manage_users",
    "view_roles",
    "manage_roles",
    "view_access_scope",
    "manage_access_scope",
    "view_sources",
    "manage_sources",
    "view_audit",
    "manage_organisations",
    "refresh_dashboard",
}


def _role_to_dict(role: Role) -> dict[str, Any]:
    permissions = role.permissions if isinstance(role.permissions, list) else []
    created_iso = (
        role.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if role.created_at
        else _now_iso()
    )
    return {
        "id": role.id,
        "name": role.name,
        "description": role.description or "",
        "permissions": sorted(permissions),
        "isSystem": role.protected,
        "isLocked": role.id == "role_owner",
        "createdAt": created_iso,
        "updatedAt": created_iso,
    }


def list_roles() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(select(Role).order_by(Role.created_at))
        return [_role_to_dict(r) for r in result.scalars().all()]

    return run_db(_query)


def get_role(role_id: str) -> dict[str, Any]:
    cached = _role_cache.get(f"role:{role_id}")
    if cached is not None:
        return cached

    async def _query(session):
        role = await session.get(Role, role_id)
        if not role:
            raise ValueError(f"Role not found: {role_id}")
        return _role_to_dict(role)

    result = run_db(_query)
    _role_cache.set(f"role:{role_id}", result)
    return result


def get_role_by_slug(slug: str) -> dict[str, Any]:
    cached = _role_cache.get(f"slug:{slug}")
    if cached is not None:
        return cached

    # Keeping this for compatibility with legacy 'role' string field.
    # We map common slugs to seeded IDs.
    slug_map = {
        "owner": "role_owner",
        "admin": "role_admin",
        "security": "role_security",
        "viewer": "role_viewer",
    }
    role_id = slug_map.get(slug, slug)

    async def _query(session):
        role = await session.get(Role, role_id)
        if not role:
            raise ValueError(f"Role not found: {slug}")
        return _role_to_dict(role)

    result = run_db(_query)
    _role_cache.set(f"slug:{slug}", result)
    return result


def create_role(input: dict[str, Any]) -> dict[str, Any]:
    role_id = input.get("id") or f"role_{str(uuid.uuid4())}"

    async def _query(session):
        role = Role(
            id=role_id,
            name=input["name"],
            description=input.get("description", ""),
            permissions=sorted(input.get("permissions", [])),
            protected=False,
        )
        session.add(role)
        await session.flush()
        await session.refresh(role)
        return _role_to_dict(role)

    return run_db(_query)


def update_role(role_id: str, input: dict[str, Any]) -> dict[str, Any]:
    async def _query(session):
        role = await session.get(Role, role_id)
        if not role:
            raise ValueError(f"Role not found: {role_id}")
        if role.id == "role_owner":
            raise ValueError("Owner role is protected")
        role.name = input["name"]
        role.description = input["description"]
        role.permissions = sorted(input.get("permissions", []))
        await session.flush()
        await session.refresh(role)
        return _role_to_dict(role)

    result = run_db(_query)
    _role_cache.invalidate()
    return result


def delete_role(role_id: str) -> None:
    async def _query(session):
        role = await session.get(Role, role_id)
        if not role:
            raise ValueError(f"Role not found: {role_id}")
        if role.id == "role_owner":
            raise ValueError("Owner role is protected")
        await session.delete(role)

    run_db(_query)
    _role_cache.invalidate()
