"""Workspace service layer — teams, users, roles, grants."""
from __future__ import annotations

import hashlib
import os
import re
import secrets as _secrets
from datetime import datetime, timezone
from typing import Any, Optional

import strawberry
from graphql import GraphQLError

from src.authz.enforcement import has_permission
from src.graphql.resolver_utils import raise_permission_denied
from src.authz.permissions.catalog import (
    MANAGE_ORGANISATIONS,
    MANAGE_ROLES,
    MANAGE_USERS,
    VIEW_ROLES,
    VIEW_SETTINGS,
    VIEW_USERS,
)
from src.authz.teams.service import (
    OrganisationNotFoundError,
    OrganisationStoreError,
    OrganisationValidationError,
    build_sharing_index,
    create_team as _create_team,
    delete_team as _delete_team,
    list_teams,
    list_admin_team_ids,
    remove_member,
    update_team as _update_team,
    upsert_member,
)
from src.authz.roles.service import (
    create_role as _create_role,
    delete_role as _delete_role,
    get_role,
    get_role_by_slug,
    list_roles,
    role_kind_from_id,
    update_role as _update_role,
)
from src.authz.permissions.service import has_role_permission, resolve_role_permissions
from src.authz.permissions.catalog import MANAGE_OWNER_ROLE
from src.db.helpers import run_db
from src.db.models import User
from src.settings.audit_stream.service import record_event
from src.authz.teams.grants import (
    add_grant as _add_grant,
    list_grants,
    remove_grant as _remove_grant,
)
from src.shared.paths import now_iso as _now_iso

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


# ---------------------------------------------------------------------------
# Strawberry types
# ---------------------------------------------------------------------------

@strawberry.type
class WorkspaceTeamMember:
    user_id: str
    source: str


@strawberry.type
class WorkspaceTeamAsset:
    asset_id: str
    type: str
    display_name: str
    external_ref: str
    source: str


@strawberry.type
class WorkspaceTeam:
    id: strawberry.ID
    name: str
    description: str
    source: str
    members: list[WorkspaceTeamMember]
    assets: list[WorkspaceTeamAsset]
    is_shared: bool
    created_at: str
    updated_at: str


@strawberry.type
class WorkspaceUser:
    id: strawberry.ID
    username: str
    email: str
    role: str
    role_id: str
    status: str
    created_at: str
    updated_at: str
    password_reset_required: bool
    totp_enabled: bool


@strawberry.type
class WorkspaceUserDirectoryEntry:
    id: strawberry.ID
    username: str
    email: str
    role: str
    status: str


@strawberry.type
class WorkspaceRole:
    id: strawberry.ID
    name: str
    description: str
    permissions: list[str]
    is_system: bool
    is_locked: bool
    created_at: str
    updated_at: str


@strawberry.type
class WorkspaceGrant:
    subject_type: str
    subject_id: str
    asset_id: str
    asset_type: str
    asset_display_name: str
    asset_external_ref: str
    source: str
    created_at: str


@strawberry.type
class WorkspaceMutationResult:
    ok: bool


# ---------------------------------------------------------------------------
# Input types
# ---------------------------------------------------------------------------

@strawberry.input
class TeamInput:
    name: str
    description: str = ""


@strawberry.input
class UserCreateInput:
    username: str
    email: str
    password: str
    role: str = "viewer"
    role_id: Optional[str] = None


@strawberry.input
class UserRoleInput:
    role: Optional[str] = None
    role_id: Optional[str] = None


@strawberry.input
class RoleInput:
    name: str
    description: str = ""
    permissions: list[str] = strawberry.field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _require_permission(ctx: dict, permission: str) -> None:
    if not has_permission(ctx["request"], permission):
        raise_permission_denied(f"Permission denied: {permission}")


def _check_feature(ctx: dict, feature: str) -> None:
    from src.license.limits import check_feature
    check_feature(ctx["request"], feature)


def _check_limit(ctx: dict, limit_key: str, current_count: int) -> None:
    from src.license.limits import check_limit
    check_limit(ctx["request"], limit_key, current_count)


def _map_team_error(exc: Exception) -> GraphQLError:
    code = "NOT_FOUND" if isinstance(exc, OrganisationNotFoundError) else "VALIDATION_ERROR"
    return GraphQLError(str(exc), extensions={"code": code})


def _team_from_dict(d: dict[str, Any], is_shared: bool) -> WorkspaceTeam:
    return WorkspaceTeam(
        id=d["id"],
        name=d["name"],
        description=d.get("description", ""),
        source=d.get("source", "manual"),
        members=[
            WorkspaceTeamMember(user_id=m["userId"], source=m.get("source", "manual"))
            for m in d.get("members", [])
        ],
        assets=[
            WorkspaceTeamAsset(
                asset_id=a["assetId"],
                type=a["type"],
                display_name=a["displayName"],
                external_ref=a["externalRef"],
                source=a.get("source", "manual"),
            )
            for a in d.get("assets", [])
        ],
        is_shared=is_shared,
        created_at=d.get("createdAt", _now_iso()),
        updated_at=d.get("updatedAt", _now_iso()),
    )


def _user_from_dict(d: dict[str, Any]) -> WorkspaceUser:
    return WorkspaceUser(
        id=d["id"],
        username=d["username"],
        email=d.get("email", ""),
        role=d.get("role", "viewer"),
        role_id=d.get("roleId", ""),
        status=d.get("status", "active"),
        created_at=d.get("createdAt", _now_iso()),
        updated_at=d.get("updatedAt", _now_iso()),
        password_reset_required=d.get("passwordResetRequired", False),
        totp_enabled=d.get("totpEnabled", False),
    )


def _user_dir_from_dict(d: dict[str, Any]) -> WorkspaceUserDirectoryEntry:
    return WorkspaceUserDirectoryEntry(
        id=d["id"],
        username=d["username"],
        email=d.get("email", ""),
        role=d.get("role", "viewer"),
        status=d.get("status", "active"),
    )


def _role_from_dict(d: dict[str, Any]) -> WorkspaceRole:
    return WorkspaceRole(
        id=d["id"],
        name=d["name"],
        description=d.get("description", ""),
        permissions=d.get("permissions", []),
        is_system=d.get("isSystem", False),
        is_locked=d.get("isLocked", False),
        created_at=d.get("createdAt", _now_iso()),
        updated_at=d.get("updatedAt", _now_iso()),
    )


def _grant_from_dict(d: dict[str, Any]) -> WorkspaceGrant:
    return WorkspaceGrant(
        subject_type=d["subjectType"],
        subject_id=d["subjectId"],
        asset_id=d["assetId"],
        asset_type=d.get("assetType", ""),
        asset_display_name=d.get("assetDisplayName", ""),
        asset_external_ref=d.get("assetExternalRef", ""),
        source=d.get("source", "manual"),
        created_at=d.get("createdAt", _now_iso()),
    )


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


def _lookup_username(user_id: str | None) -> str | None:
    if not user_id:
        return None

    async def _q(session):
        user = await session.get(User, user_id)
        return user.username if user else None

    return run_db(_q)


# ---------------------------------------------------------------------------
# Query resolvers
# ---------------------------------------------------------------------------

def teams(*, info_context: dict) -> list[WorkspaceTeam]:
    _require_permission(info_context, VIEW_SETTINGS)
    user_id = info_context.get("user_id")
    teams_data = list_teams()
    sharing = build_sharing_index(user_id) if user_id else {}
    return [_team_from_dict(t, sharing.get(t["id"], False)) for t in teams_data]


def users(*, info_context: dict) -> list[WorkspaceUser]:
    _require_permission(info_context, MANAGE_USERS)

    from sqlalchemy import select

    async def _q(session):
        result = await session.execute(select(User))
        return result.scalars().all()

    rows = run_db(_q)
    now = _now_iso()

    def _row_to_dict(u: User) -> dict[str, Any]:
        created = (
            u.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if u.created_at else now
        )
        updated = (
            u.updated_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if u.updated_at else created
        )
        return {
            "id": u.id,
            "username": u.username,
            "email": u.email or "",
            "role": role_kind_from_id(u.role_id),
            "roleId": u.role_id or "",
            "status": u.status or "active",
            "createdAt": created,
            "updatedAt": updated,
            "passwordResetRequired": u.password_reset_required or False,
            "totpEnabled": u.totp_enabled or False,
        }

    return [_user_from_dict(_row_to_dict(u)) for u in rows]


def user_directory(*, info_context: dict) -> list[WorkspaceUserDirectoryEntry]:
    request = info_context["request"]
    user_id = info_context.get("user_id") or ""
    is_workspace_admin = has_permission(request, VIEW_USERS)
    admin_teams = list_admin_team_ids(user_id) if user_id else []
    if not is_workspace_admin and not admin_teams:
        raise_permission_denied("Permission denied: user directory access")

    from sqlalchemy import select

    async def _q(session):
        result = await session.execute(select(User))
        return result.scalars().all()

    rows = run_db(_q)
    return [
        WorkspaceUserDirectoryEntry(
            id=u.id,
            username=u.username,
            email=u.email or "",
            role=role_kind_from_id(u.role_id),
            status=u.status or "active",
        )
        for u in rows
    ]


def roles(*, info_context: dict) -> list[WorkspaceRole]:
    _require_permission(info_context, VIEW_ROLES)
    return [_role_from_dict(r) for r in list_roles()]


def role(*, role_id: str, info_context: dict) -> Optional[WorkspaceRole]:
    _require_permission(info_context, VIEW_ROLES)
    try:
        return _role_from_dict(get_role(role_id))
    except ValueError:
        return None


def grants(
    *,
    subject_type: Optional[str] = None,
    subject_id: Optional[str] = None,
    asset_id: Optional[str] = None,
    info_context: dict,
) -> list[WorkspaceGrant]:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    return [
        _grant_from_dict(g)
        for g in list_grants(
            subject_type=subject_type,
            subject_id=subject_id,
            asset_id=asset_id,
        )
    ]


# ---------------------------------------------------------------------------
# Team mutation resolvers
# ---------------------------------------------------------------------------

def create_team(*, input: TeamInput, info_context: dict) -> WorkspaceTeam:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    _check_feature(info_context, "teams")
    actor_id = info_context.get("user_id")
    try:
        team = _create_team({"name": input.name, "description": input.description}, actor_user_id=actor_id)
    except (OrganisationNotFoundError, OrganisationValidationError) as exc:
        raise _map_team_error(exc)
    except OrganisationStoreError as exc:
        raise GraphQLError(str(exc), extensions={"code": "INTERNAL_ERROR"}) from exc
    record_event(
        action="team.created",
        actor_user_id=actor_id,
        target=team["id"],
        metadata={"name": team["name"]},
    )
    return _team_from_dict(team, False)


def update_team(*, team_id: str, input: TeamInput, info_context: dict) -> WorkspaceTeam:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    actor_id = info_context.get("user_id")
    try:
        team = _update_team(team_id, {"name": input.name, "description": input.description})
    except (OrganisationNotFoundError, OrganisationValidationError) as exc:
        raise _map_team_error(exc)
    except OrganisationStoreError as exc:
        raise GraphQLError(str(exc), extensions={"code": "INTERNAL_ERROR"}) from exc
    record_event(
        action="team.updated",
        actor_user_id=actor_id,
        target=team_id,
        metadata={"name": team["name"]},
    )
    sharing = build_sharing_index(actor_id) if actor_id else {}
    return _team_from_dict(team, sharing.get(team_id, False))


def delete_team(*, team_id: str, info_context: dict) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    actor_id = info_context.get("user_id")
    try:
        _delete_team(team_id)
    except OrganisationNotFoundError as exc:
        raise GraphQLError(str(exc), extensions={"code": "NOT_FOUND"}) from exc
    record_event(action="team.deleted", actor_user_id=actor_id, target=team_id)
    return WorkspaceMutationResult(ok=True)


def add_team_member(*, team_id: str, user_id: str, info_context: dict) -> WorkspaceTeam:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    actor_id = info_context.get("user_id")
    try:
        team = upsert_member(team_id, user_id)
    except (OrganisationNotFoundError, OrganisationValidationError) as exc:
        raise _map_team_error(exc)
    record_event(
        action="team.member.added",
        actor_user_id=actor_id,
        target=team_id,
        metadata={"userId": user_id},
    )
    sharing = build_sharing_index(actor_id) if actor_id else {}
    return _team_from_dict(team, sharing.get(team_id, False))


def remove_team_member(*, team_id: str, user_id: str, info_context: dict) -> WorkspaceTeam:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    actor_id = info_context.get("user_id")
    try:
        team = remove_member(team_id, user_id)
    except (OrganisationNotFoundError, OrganisationValidationError) as exc:
        raise _map_team_error(exc)
    record_event(
        action="team.member.removed",
        actor_user_id=actor_id,
        target=team_id,
        metadata={"userId": user_id},
    )
    sharing = build_sharing_index(actor_id) if actor_id else {}
    return _team_from_dict(team, sharing.get(team_id, False))


# ---------------------------------------------------------------------------
# User mutation resolvers
# ---------------------------------------------------------------------------

def create_user(*, input: UserCreateInput, info_context: dict) -> WorkspaceUser:
    _require_permission(info_context, MANAGE_USERS)
    actor_id = info_context.get("user_id") or ""
    actor_role = info_context.get("role") or "viewer"
    actor_role_id = info_context.get("role_id")

    from sqlalchemy import select, func as _func

    async def _count(session):
        result = await session.execute(
            select(_func.count()).select_from(User).where(User.status != "disabled")
        )
        return result.scalar() or 0

    active_count = run_db(_count)
    _check_limit(info_context, "max_users", active_count)

    username = input.username.strip()
    email = input.email.strip().lower()
    password = input.password

    if not username:
        raise GraphQLError("Username is required.", extensions={"code": "VALIDATION_ERROR"})
    if not email or not _EMAIL_RE.match(email):
        raise GraphQLError("Invalid email address.", extensions={"code": "VALIDATION_ERROR"})
    if len(password) < 12:
        raise GraphQLError("Password must be at least 12 characters long.", extensions={"code": "VALIDATION_ERROR"})

    if input.role_id:
        try:
            role_record = get_role(input.role_id)
        except ValueError:
            raise GraphQLError("Invalid role.", extensions={"code": "VALIDATION_ERROR"})
        resolved_role_id = role_record["id"]
    else:
        role_slug = input.role.strip()
        if role_slug not in ("owner", "admin", "security", "viewer"):
            raise GraphQLError("Invalid role.", extensions={"code": "VALIDATION_ERROR"})
        try:
            role_record = get_role_by_slug(role_slug)
        except ValueError:
            raise GraphQLError("Invalid role.", extensions={"code": "VALIDATION_ERROR"})
        resolved_role_id = role_record["id"]

    new_role_kind = role_kind_from_id(resolved_role_id)
    if new_role_kind == "owner" and not has_role_permission(actor_role, actor_role_id, MANAGE_OWNER_ROLE):
        raise_permission_denied("Only roles with manage_owner_role can promote to owner.")

    password_hash = _hash_password(password)
    new_user_id = f"usr_{_secrets.token_hex(12)}"

    from sqlalchemy import select, func as _func2

    async def _insert(session):
        result = await session.execute(
            select(User).where(_func2.lower(User.username) == username.lower())
        )
        if result.scalars().first():
            raise GraphQLError("User already exists.", extensions={"code": "VALIDATION_ERROR"})
        result = await session.execute(
            select(User).where(_func2.lower(User.email) == email)
        )
        if result.scalars().first():
            raise GraphQLError("Email already in use.", extensions={"code": "VALIDATION_ERROR"})
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
        now_iso = now.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email or "",
            "role": role_kind_from_id(user.role_id),
            "roleId": user.role_id or "",
            "status": user.status or "active",
            "createdAt": now_iso,
            "updatedAt": now_iso,
            "passwordResetRequired": False,
            "totpEnabled": False,
        }

    new_user = run_db(_insert)
    actor_username = _lookup_username(actor_id)
    record_event(
        action="user.created",
        actor_user_id=actor_id,
        actor_username=actor_username,
        target=new_user["id"],
        metadata={"username": username, "email": email, "role": new_role_kind},
    )
    return _user_from_dict(new_user)


def update_user_role(*, user_id: str, input: UserRoleInput, info_context: dict) -> WorkspaceUser:
    _require_permission(info_context, MANAGE_USERS)
    actor_id = info_context.get("user_id") or ""
    actor_role = info_context.get("role") or "viewer"
    actor_role_id = info_context.get("role_id")

    if actor_id == user_id:
        raise GraphQLError("You cannot change your own role.", extensions={"code": "VALIDATION_ERROR"})

    if input.role_id:
        try:
            role_record = get_role(input.role_id)
        except ValueError:
            raise GraphQLError("Role not found.", extensions={"code": "NOT_FOUND"})
    elif input.role:
        role_slug = input.role.strip()
        try:
            role_record = get_role_by_slug(role_slug)
        except ValueError:
            raise GraphQLError("Role not found.", extensions={"code": "NOT_FOUND"})
    else:
        raise GraphQLError("Either role or roleId must be provided.", extensions={"code": "VALIDATION_ERROR"})

    new_role_id = role_record["id"]
    new_role_kind = role_kind_from_id(new_role_id)

    if actor_role != "owner":
        try:
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
            raise_permission_denied(
                f"Cannot assign role with permissions you don't hold: {', '.join(sorted(escalated))}"
            )

    from sqlalchemy import select, func as _func

    async def _update(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})

        current_role_id = user.role_id
        current_role_kind = role_kind_from_id(current_role_id)

        if (current_role_kind == "owner" or new_role_kind == "owner") and \
                not has_role_permission(actor_role, actor_role_id, MANAGE_OWNER_ROLE):
            raise_permission_denied("Only roles with manage_owner_role can modify owner users.")

        result = await session.execute(
            select(_func.count()).select_from(User).where(
                User.role_id == "role_owner", User.status == "active"
            )
        )
        owner_count = result.scalar() or 0
        if (
            current_role_id == "role_owner"
            and new_role_id != "role_owner"
            and user.status == "active"
            and owner_count <= 1
        ):
            raise GraphQLError("Cannot demote the last active owner.", extensions={"code": "VALIDATION_ERROR"})

        if current_role_id == new_role_id:
            now_iso = _now_iso()
            _created = (
                user.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                if user.created_at else now_iso
            )
            _updated = (
                user.updated_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
                if user.updated_at else _created
            )
            return {
                "id": user.id, "username": user.username, "email": user.email or "",
                "role": current_role_kind, "roleId": user.role_id or "",
                "status": user.status or "active", "createdAt": _created, "updatedAt": _updated,
                "passwordResetRequired": user.password_reset_required or False,
                "totpEnabled": user.totp_enabled or False,
            }, current_role_kind, False

        user.role_id = new_role_id
        user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        now_iso = user.updated_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        created_iso = (
            user.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if user.created_at else now_iso
        )
        return {
            "id": user.id, "username": user.username, "email": user.email or "",
            "role": role_kind_from_id(user.role_id), "roleId": user.role_id or "",
            "status": user.status or "active", "createdAt": created_iso, "updatedAt": now_iso,
            "passwordResetRequired": user.password_reset_required or False,
            "totpEnabled": user.totp_enabled or False,
        }, current_role_kind, True

    user_dict, old_role, changed = run_db(_update)
    if changed:
        actor_username = _lookup_username(actor_id)
        record_event(
            action="user.role_updated",
            actor_user_id=actor_id,
            actor_username=actor_username,
            target=user_id,
            metadata={"old_role": old_role, "new_role": new_role_kind, "roleId": new_role_id},
        )
    return _user_from_dict(user_dict)


def _set_user_status(*, user_id: str, status: str, action: str, info_context: dict) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_USERS)
    actor_id = info_context.get("user_id") or ""

    from sqlalchemy import select, func as _func

    async def _update(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        if status == "disabled":
            result = await session.execute(
                select(_func.count()).select_from(User).where(
                    User.role_id == "role_owner", User.status == "active"
                )
            )
            owner_count = result.scalar() or 0
            if user.role_id == "role_owner" and user.status == "active" and owner_count <= 1:
                raise GraphQLError(
                    "Cannot disable the last active owner.",
                    extensions={"code": "VALIDATION_ERROR"},
                )
        user.status = status
        if status == "disabled":
            user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return user.username

    username = run_db(_update)
    actor_username = _lookup_username(actor_id)
    record_event(
        action=action,
        actor_user_id=actor_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": username},
    )
    return WorkspaceMutationResult(ok=True)


def enable_user(*, user_id: str, info_context: dict) -> WorkspaceMutationResult:
    return _set_user_status(user_id=user_id, status="active", action="user.enabled", info_context=info_context)


def disable_user(*, user_id: str, info_context: dict) -> WorkspaceMutationResult:
    return _set_user_status(user_id=user_id, status="disabled", action="user.disabled", info_context=info_context)


def reset_user_password(*, user_id: str, password: str, info_context: dict) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_USERS)
    actor_id = info_context.get("user_id") or ""

    if len(password) < 12:
        raise GraphQLError("Password must be at least 12 characters long.", extensions={"code": "VALIDATION_ERROR"})

    password_hash = _hash_password(password)

    async def _update(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        user.password_hash = password_hash
        user.session_version = (user.session_version or 1) + 1
        user.updated_at = datetime.now(timezone.utc)
        await session.flush()
        return user.username

    username = run_db(_update)
    actor_username = _lookup_username(actor_id)
    record_event(
        action="user.password_reset",
        actor_user_id=actor_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": username},
    )
    return WorkspaceMutationResult(ok=True)


def delete_user_mutation(*, user_id: str, info_context: dict) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_USERS)
    actor_id = info_context.get("user_id") or ""
    actor_role = info_context.get("role") or "viewer"
    actor_role_id = info_context.get("role_id")

    if actor_id == user_id:
        raise GraphQLError("You cannot delete your own account.", extensions={"code": "VALIDATION_ERROR"})

    from sqlalchemy import select, func as _func

    async def _delete(session):
        user = await session.get(User, user_id)
        if user is None:
            raise GraphQLError("User not found.", extensions={"code": "NOT_FOUND"})
        if user.role_id == "role_owner" and not has_role_permission(actor_role, actor_role_id, MANAGE_OWNER_ROLE):
            raise_permission_denied("Only roles with manage_owner_role can delete owner users.")
        result = await session.execute(
            select(_func.count()).select_from(User).where(
                User.role_id == "role_owner", User.status == "active"
            )
        )
        owner_count = result.scalar() or 0
        if user.role_id == "role_owner" and user.status == "active" and owner_count <= 1:
            raise GraphQLError("Cannot delete the last active owner.", extensions={"code": "VALIDATION_ERROR"})
        username = user.username
        role = role_kind_from_id(user.role_id)
        await session.delete(user)
        return username, role

    username, role = run_db(_delete)
    actor_username = _lookup_username(actor_id)
    record_event(
        action="user.deleted",
        actor_user_id=actor_id,
        actor_username=actor_username,
        target=user_id,
        metadata={"username": username, "role": role},
    )
    return WorkspaceMutationResult(ok=True)


# ---------------------------------------------------------------------------
# Role mutation resolvers
# ---------------------------------------------------------------------------

def create_role_mutation(*, input: RoleInput, info_context: dict) -> WorkspaceRole:
    _require_permission(info_context, MANAGE_ROLES)
    _check_feature(info_context, "custom_roles")
    role_data = _create_role({
        "name": input.name,
        "description": input.description,
        "permissions": input.permissions,
    })
    return _role_from_dict(role_data)


def update_role_mutation(*, role_id: str, input: RoleInput, info_context: dict) -> WorkspaceRole:
    _require_permission(info_context, MANAGE_ROLES)
    try:
        role_data = _update_role(role_id, {
            "name": input.name,
            "description": input.description,
            "permissions": input.permissions,
        })
    except ValueError as exc:
        code = "PERMISSION_DENIED" if "protected" in str(exc) else "NOT_FOUND"
        raise GraphQLError(str(exc), extensions={"code": code}) from exc
    return _role_from_dict(role_data)


def delete_role_mutation(
    *,
    role_id: str,
    replacement_role_id: Optional[str] = None,
    info_context: dict,
) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_ROLES)

    if replacement_role_id:
        try:
            get_role(replacement_role_id)
        except ValueError:
            raise GraphQLError("Replacement role not found.", extensions={"code": "NOT_FOUND"})

    from sqlalchemy import select, func as _func
    from src.db.models import User as _User

    async def _reassign(session):
        result = await session.execute(
            select(_func.count()).select_from(_User).where(_User.role_id == role_id)
        )
        in_use = (result.scalar() or 0) > 0
        if in_use and not replacement_role_id:
            raise GraphQLError(
                "Role is assigned to users. Must provide replacementRoleId.",
                extensions={"code": "VALIDATION_ERROR"},
            )
        if in_use and replacement_role_id:
            result = await session.execute(select(_User).where(_User.role_id == role_id))
            now = datetime.now(timezone.utc)
            for user in result.scalars().all():
                user.role_id = replacement_role_id
                user.session_version = (user.session_version or 1) + 1
                user.updated_at = now

    run_db(_reassign)

    try:
        _delete_role(role_id)
    except ValueError as exc:
        code = "PERMISSION_DENIED" if "protected" in str(exc) else "NOT_FOUND"
        raise GraphQLError(str(exc), extensions={"code": code}) from exc

    return WorkspaceMutationResult(ok=True)


# ---------------------------------------------------------------------------
# Grant mutation resolvers
# ---------------------------------------------------------------------------

def add_grant_mutation(
    *,
    subject_type: str,
    subject_id: str,
    asset_id: str,
    source: str = "manual",
    info_context: dict,
) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    if subject_type not in ("user", "team"):
        raise GraphQLError(
            "subjectType must be 'user' or 'team'.",
            extensions={"code": "VALIDATION_ERROR"},
        )
    actor_id = info_context.get("user_id")
    try:
        _add_grant(subject_type=subject_type, subject_id=subject_id, asset_id=asset_id, source=source)
    except ValueError as exc:
        raise GraphQLError(str(exc), extensions={"code": "NOT_FOUND"}) from exc
    record_event(
        action="grant.added",
        actor_user_id=actor_id,
        target=subject_id,
        metadata={"subjectType": subject_type, "assetId": asset_id, "source": source},
    )
    return WorkspaceMutationResult(ok=True)


def remove_grant_mutation(
    *,
    subject_type: str,
    subject_id: str,
    asset_id: str,
    info_context: dict,
) -> WorkspaceMutationResult:
    _require_permission(info_context, MANAGE_ORGANISATIONS)
    if subject_type not in ("user", "team"):
        raise GraphQLError(
            "subjectType must be 'user' or 'team'.",
            extensions={"code": "VALIDATION_ERROR"},
        )
    actor_id = info_context.get("user_id")
    _remove_grant(subject_type=subject_type, subject_id=subject_id, asset_id=asset_id)
    record_event(
        action="grant.removed",
        actor_user_id=actor_id,
        target=subject_id,
        metadata={"subjectType": subject_type, "assetId": asset_id},
    )
    return WorkspaceMutationResult(ok=True)
