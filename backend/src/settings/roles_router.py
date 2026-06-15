from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from src.settings.roles_store import (
    create_role,
    delete_role,
    get_role,
    list_roles,
    update_role,
)
from src.settings.router import require_permission
from src.settings.schemas import DeleteRoleRequest, RoleRequest

roles_router = APIRouter(prefix="/api/v1/settings/roles", tags=["roles"])


@roles_router.get("")
def get_roles(request: Request) -> JSONResponse:
    require_permission(request, "view_roles")
    return JSONResponse({"roles": list_roles()})


@roles_router.post("")
def post_role(body: RoleRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_roles")
    # License: custom roles feature gate
    from src.license.limits import check_feature
    check_feature(request, "custom_roles")
    role = create_role(body.model_dump())
    return JSONResponse({"role": role})


@roles_router.get("/{role_id}")
def get_role_detail(role_id: str, request: Request) -> JSONResponse:
    require_permission(request, "view_roles")
    try:
        return JSONResponse({"role": get_role(role_id)})
    except ValueError:
        raise HTTPException(status_code=404, detail="Role not found.")


@roles_router.patch("/{role_id}")
def patch_role(role_id: str, body: RoleRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_roles")
    try:
        role = update_role(role_id, body.model_dump())
        return JSONResponse({"role": role})
    except ValueError as exc:
        if "protected" in str(exc):
            raise HTTPException(status_code=403, detail="This role is protected and cannot be modified.")
        raise HTTPException(status_code=404, detail="Role not found.")


@roles_router.post("/{role_id}/duplicate")
def duplicate_role_api(role_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_roles")
    # License: custom roles feature gate
    from src.license.limits import check_feature
    check_feature(request, "custom_roles")
    try:
        original = get_role(role_id)
        new_role_input = {
            "name": f"{original['name']} Copy",
            "description": original["description"],
            "permissions": original["permissions"],
        }
        role = create_role(new_role_input)
        return JSONResponse({"role": role})
    except ValueError:
        raise HTTPException(status_code=404, detail="Role not found.")


@roles_router.delete("/{role_id}")
def delete_role_api(role_id: str, request: Request, body: DeleteRoleRequest) -> JSONResponse:
    require_permission(request, "manage_roles")
    replacement = body.replacementRoleId

    try:
        if replacement:
            get_role(replacement)  # Ensure replacement exists

        # Check if any users are assigned to this role
        from src.db.helpers import run_db
        from src.db.models import User
        from sqlalchemy import select, func
        from datetime import datetime, timezone

        async def _reassign(session):
            result = await session.execute(
                select(func.count()).select_from(User).where(User.role_id == role_id)
            )
            in_use = (result.scalar() or 0) > 0

            if in_use and not replacement:
                return False, "Role is assigned to users. Must provide replacementRoleId."

            if in_use and replacement:
                result = await session.execute(
                    select(User).where(User.role_id == role_id)
                )
                for user in result.scalars().all():
                    user.role_id = replacement
                    user.session_version = (user.session_version or 1) + 1
                    user.updated_at = datetime.now(timezone.utc)

            return True, None

        ok, error_msg = run_db(_reassign)
        if not ok:
            return JSONResponse({"detail": error_msg}, status_code=400)

        delete_role(role_id)
        return JSONResponse({"ok": True})
    except ValueError as exc:
        if "protected" in str(exc):
            raise HTTPException(status_code=403, detail="This role is protected and cannot be deleted.")
        raise HTTPException(status_code=404, detail="Role not found.")
