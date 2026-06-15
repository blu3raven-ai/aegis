from __future__ import annotations

import hashlib
import os
import secrets as _secrets
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from src.db.helpers import run_db
from src.db.models import User
from src.settings.router import require_permission, has_permission, resolve_role_permissions
from src.settings.organisations_store import list_admin_team_ids
from src.settings.roles_store import get_role, get_role_by_slug, role_kind_from_id
from src.settings.audit import record_event
from src.shared.paths import now_iso as _now_iso

_ADMIN_ROLES = {"owner", "admin"}
_VALID_ROLES = {"owner", "admin", "security", "viewer"}
_VALID_STATUSES = {"active", "disabled", "pending"}

users_router = APIRouter(prefix="/api/v1/settings/users", tags=["users-admin"])


def _user_to_dict(user: User) -> dict[str, Any]:
    created_iso = (
        user.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if user.created_at else _now_iso()
    )
    updated_iso = (
        user.updated_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        if user.updated_at else created_iso
    )
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email or "",
        "passwordHash": user.password_hash or "",
        "role": role_kind_from_id(user.role_id),
        "roleId": user.role_id,
        "status": user.status or "active",
        "createdAt": created_iso,
        "updatedAt": updated_iso,
        "passwordResetRequired": user.password_reset_required if user.password_reset_required is not None else False,
        "totpSecret": user.totp_secret,
        "totpEnabled": user.totp_enabled if user.totp_enabled is not None else False,
    }


def _safe_user(user: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in user.items() if key not in {"passwordHash", "totpSecret"}}


async def _active_owner_count_async(session) -> int:
    result = await session.execute(
        select(func.count()).select_from(User).where(User.role_id == "role_owner", User.status == "active")
    )
    return result.scalar() or 0


def _lookup_username_db(user_id: str | None) -> str | None:
    if not user_id:
        return None

    async def _query(session):
        user = await session.get(User, user_id)
        return user.username if user else None

    return run_db(_query)


def list_users_internal() -> list[dict[str, Any]]:
    """Returns a list of all users without sensitive information."""
    async def _query(session):
        result = await session.execute(select(User))
        return [_safe_user(_user_to_dict(u)) for u in result.scalars().all()]

    return run_db(_query)


def set_user_status_internal(user_id: str, status: str) -> dict[str, Any]:
    """Sets the status of a user. For internal use only."""
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status: {status}")

    async def _query(session):
        user = await session.get(User, user_id)
        if not user:
            raise ValueError(f"User not found: {user_id}")
        if user.status == status:
            return _user_to_dict(user)
        user.status = status
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _user_to_dict(user)

    return run_db(_query)


def _hash_password(password: str) -> str:
    salt = os.urandom(16)
    key = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1,
        dklen=64,
    )
    return f"scrypt:v1:{salt.hex()}:{key.hex()}"


def _validate_role(role: str) -> str:
    normalized = role.strip()
    if normalized not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(sorted(_VALID_ROLES))}")
    return normalized


_EMAIL_RE = __import__("re").compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str
    roleId: str | None = None


class UpdateRoleRequest(BaseModel):
    role: str | None = None
    roleId: str | None = None


@users_router.get("")
def list_users(request: Request) -> JSONResponse:
    require_permission(request, "manage_users")

    async def _query(session):
        result = await session.execute(select(User))
        return [_safe_user(_user_to_dict(u)) for u in result.scalars().all()]

    users = run_db(_query)
    return JSONResponse({"users": users})


@users_router.get("/directory")
def list_users_directory(request: Request) -> JSONResponse:
    user_id = str(getattr(request.state, "user_sub", "") or "")
    is_workspace_admin = has_permission(request, "view_users")
    admin_teams = list_admin_team_ids(user_id)

    if not is_workspace_admin and not admin_teams:
        raise HTTPException(status_code=403, detail="Permission denied: user directory access")

    async def _query(session):
        result = await session.execute(select(User))
        return [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email or "",
                "role": role_kind_from_id(u.role_id),
                "status": u.status or "active",
            }
            for u in result.scalars().all()
        ]

    users = run_db(_query)
    return JSONResponse({"users": users})


@users_router.post("")
def create_user(body: CreateUserRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    # License: enforce user limit
    from src.license.limits import check_limit
    active_count = sum(1 for u in list_users_internal() if u.get("status") != "disabled")
    check_limit(request, "max_users", active_count)
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")
    username = body.username.strip()
    email = body.email.strip().lower()
    password = body.password

    # Resolve role_id from roleId if provided, fall back to legacy role slug.
    if body.roleId:
        try:
            role_record = get_role(body.roleId)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid role.")
        resolved_role_id = role_record["id"]
    else:
        slug = _validate_role(body.role)
        try:
            role_record = get_role_by_slug(slug)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid role.")
        resolved_role_id = role_record["id"]
    role = role_kind_from_id(resolved_role_id)

    if not username:
        raise HTTPException(status_code=400, detail="Username is required.")
    if not email:
        raise HTTPException(status_code=400, detail="Email is required.")
    if not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if not password.strip():
        raise HTTPException(status_code=400, detail="Password is required.")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long.")
    if role == "owner" and getattr(request.state, "user_role", None) != "owner":
        raise HTTPException(status_code=403, detail="Only owners can promote to owner.")

    password_hash = _hash_password(password)
    new_user_id = f"usr_{_secrets.token_hex(12)}"

    async def _query(session):
        # Check duplicates
        result = await session.execute(select(User).where(func.lower(User.username) == username.lower()))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="User already exists.")
        result = await session.execute(select(User).where(func.lower(User.email) == email))
        if result.scalars().first():
            raise HTTPException(status_code=400, detail="Email already in use.")

        now = datetime.now(timezone.utc)
        user = User(
            id=new_user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            role_id=resolved_role_id,
            status="active",
            created_at=now,
            updated_at=now,
        )
        session.add(user)
        await session.flush()
        return _user_to_dict(user)

    new_user = run_db(_query)
    actor_username = _lookup_username_db(actor_user_id)
    record_event(
        action="user.created",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        target=new_user["id"],
        metadata={"username": username, "email": email, "role": role},
    )
    return JSONResponse({"ok": True, "user": _safe_user(new_user)})


@users_router.post("/{user_id}/disable")
def disable_user(user_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        owner_count = await _active_owner_count_async(session)
        if user.role_id == "role_owner" and user.status == "active" and owner_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot disable the last active owner.")
        user.status = "disabled"
        user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _user_to_dict(user)

    user_dict = run_db(_query)
    actor_username = _lookup_username_db(actor_user_id)
    record_event(
        action="user.disabled",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": user_dict.get("username")},
    )
    return JSONResponse({"ok": True})


@users_router.post("/{user_id}/enable")
def enable_user(user_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        user.status = "active"
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _user_to_dict(user)

    user_dict = run_db(_query)
    actor_username = _lookup_username_db(actor_user_id)
    record_event(
        action="user.enabled",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": user_dict.get("username")},
    )
    return JSONResponse({"ok": True})


@users_router.patch("/{user_id}/role")
def update_user_role(user_id: str, body: UpdateRoleRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")
    actor_role = str(getattr(request.state, "user_role", "") or "")

    # Resolve target role_id (truth) and derived kind from either roleId or slug.
    if body.roleId:
        try:
            role_record = get_role(body.roleId)
        except ValueError:
            raise HTTPException(status_code=404, detail="Role not found.")
    elif body.role:
        slug = _validate_role(body.role)
        try:
            role_record = get_role_by_slug(slug)
        except ValueError:
            raise HTTPException(status_code=404, detail="Role not found.")
    else:
        raise HTTPException(status_code=400, detail="Either role or roleId must be provided.")

    new_role_id = role_record["id"]
    new_role_kind = role_kind_from_id(new_role_id)

    if actor_user_id == user_id:
        raise HTTPException(status_code=400, detail="You cannot change your own role.")

    # Non-owners cannot assign roles with permissions they don't hold themselves.
    if actor_role != "owner":
        try:
            actor_role_id = getattr(request.state, "user_role_id", None)
            if isinstance(actor_role_id, str) and actor_role_id:
                actor_record = get_role(actor_role_id)
            else:
                actor_record = get_role_by_slug(actor_role)
            actor_perms = resolve_role_permissions(actor_record)
        except ValueError:
            actor_perms = set()

        target_perms = resolve_role_permissions(role_record)

        escalated = target_perms - actor_perms
        if escalated:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot assign role with permissions you don't hold: {', '.join(sorted(escalated))}",
            )

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")

        current_role_id = user.role_id
        current_role_kind = role_kind_from_id(current_role_id)

        if actor_role != "owner" and (current_role_kind == "owner" or new_role_kind == "owner"):
            raise HTTPException(status_code=403, detail="Only owners can update owner users.")

        owner_count = await _active_owner_count_async(session)
        if (
            current_role_id == "role_owner"
            and new_role_id != "role_owner"
            and user.status == "active"
            and owner_count <= 1
        ):
            raise HTTPException(status_code=400, detail="Cannot demote the last active owner.")

        if current_role_id == new_role_id:
            return _user_to_dict(user), current_role_kind, False

        user.role_id = new_role_id
        user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _user_to_dict(user), current_role_kind, True

    user_dict, old_role, changed = run_db(_query)
    if changed:
        actor_username = _lookup_username_db(actor_user_id)
        record_event(
            action="user.role_updated",
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            target=user_id,
            metadata={"old_role": old_role, "new_role": new_role_kind, "roleId": new_role_id},
        )
    return JSONResponse({"ok": True, "user": _safe_user(user_dict)})


class ResetPasswordRequest(BaseModel):
    password: str


@users_router.post("/{user_id}/reset-password")
def reset_password(user_id: str, body: ResetPasswordRequest, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")
    password = body.password

    if not password.strip():
        raise HTTPException(status_code=400, detail="Password is required.")
    if len(password) < 12:
        raise HTTPException(status_code=400, detail="Password must be at least 12 characters long.")

    password_hash = _hash_password(password)

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        user.password_hash = password_hash
        user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return _user_to_dict(user)

    user_dict = run_db(_query)
    actor_username = _lookup_username_db(actor_user_id)
    record_event(
        action="user.password_reset",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": user_dict.get("username")},
    )
    return JSONResponse({"ok": True})


@users_router.delete("/{user_id}")
def delete_user(user_id: str, request: Request) -> JSONResponse:
    require_permission(request, "manage_users")
    actor_user_id = str(getattr(request.state, "user_sub", "") or "")
    actor_role = str(getattr(request.state, "user_role", "") or "")
    if actor_user_id == user_id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    async def _query(session):
        user = await session.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")
        target_is_owner = user.role_id == "role_owner"
        if actor_role != "owner" and target_is_owner:
            raise HTTPException(status_code=403, detail="Only owners can delete owner users.")
        owner_count = await _active_owner_count_async(session)
        if target_is_owner and user.status == "active" and owner_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot delete the last active owner.")
        user_dict = _user_to_dict(user)
        await session.delete(user)
        return user_dict

    deleted_user = run_db(_query)
    actor_username = _lookup_username_db(actor_user_id)
    record_event(
        action="user.deleted",
        actor_user_id=actor_user_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": deleted_user.get("username"), "role": deleted_user.get("role")},
    )
    return JSONResponse({"ok": True})
