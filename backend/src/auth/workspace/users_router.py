"""Workspace user-administration endpoints.

Lives next to auth/account/ on the auth REST surface — both manage
identity, and grouping them keeps the auth surface contiguous. Delegates
to ``src.auth.workspace.service`` for the shared business logic.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends
from graphql import GraphQLError
from pydantic import BaseModel, Field

from src.auth._gql_errors import raise_for_gql
from src.auth.workspace.service import (
    UserCreateInput,
    UserRoleInput,
    create_user as _create_user,
    delete_user_mutation as _delete_user,
    disable_user as _disable_user,
    enable_user as _enable_user,
    reset_user_password as _reset_user_password,
    update_user_role as _update_user_role,
    users as _list_users,
)
from src.authz.enforcement.dependencies import Permission, caller_context
from src.authz.permissions.catalog import MANAGE_USERS

_logger = logging.getLogger(__name__)

users_router = APIRouter(prefix="/api/v1/workspace/users", tags=["workspace"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"
    roleId: Optional[str] = Field(default=None)


class UpdateRoleRequest(BaseModel):
    role: Optional[str] = None
    roleId: Optional[str] = None


class ResetPasswordRequest(BaseModel):
    password: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _user_to_dict(user) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": user.role,
        "roleId": user.role_id,
        "status": user.status,
        "createdAt": user.created_at,
        "updatedAt": user.updated_at,
        "passwordResetRequired": user.password_reset_required,
        "totpEnabled": user.totp_enabled,
    }


def list_users_internal() -> list[dict]:
    """Permission-free user list for internal counters (e.g. license usage)."""
    from sqlalchemy import select

    from src.db.helpers import run_db
    from src.db.models import User

    async def _q(session):
        result = await session.execute(select(User))
        return result.scalars().all()

    rows = run_db(_q)
    return [{"id": u.id, "status": u.status or "active"} for u in rows]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@users_router.get("")
def list_users(
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    try:
        result = _list_users(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"users": [_user_to_dict(u) for u in result]}


@users_router.post("", status_code=201)
def create_user(
    body: CreateUserRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    payload = UserCreateInput(
        username=body.username,
        email=body.email,
        password=body.password,
        role=body.role,
        role_id=body.roleId,
    )
    try:
        user = _create_user(input=payload, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _user_to_dict(user)


@users_router.post("/{user_id}/enable")
def enable_user(
    user_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    try:
        _enable_user(user_id=user_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@users_router.post("/{user_id}/disable")
def disable_user(
    user_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    try:
        _disable_user(user_id=user_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@users_router.patch("/{user_id}/role")
def update_user_role(
    user_id: str,
    body: UpdateRoleRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    payload = UserRoleInput(role=body.role, role_id=body.roleId)
    try:
        user = _update_user_role(
            user_id=user_id, input=payload, info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _user_to_dict(user)


@users_router.post("/{user_id}/reset-password")
def reset_user_password(
    user_id: str,
    body: ResetPasswordRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    try:
        _reset_user_password(
            user_id=user_id, password=body.password, info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@users_router.delete("/{user_id}")
def delete_user(
    user_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_USERS)),
) -> dict:
    try:
        _delete_user(user_id=user_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}
