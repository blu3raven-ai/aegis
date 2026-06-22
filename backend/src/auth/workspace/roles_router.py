"""Workspace role-administration endpoints.

Lives next to auth/workspace/users_router on the auth REST surface — both
manage workspace identity, and grouping them keeps the auth surface
contiguous. Delegates to ``src.auth.workspace.service`` for the shared
business logic.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from graphql import GraphQLError
from pydantic import BaseModel, Field

from src.auth._gql_errors import raise_for_gql
from src.auth.workspace.service import (
    RoleInput,
    create_role_mutation as _create_role,
    delete_role_mutation as _delete_role,
    role as _get_role,
    roles as _list_roles,
    update_role_mutation as _update_role,
)
from src.authz.enforcement.dependencies import Permission, caller_context
from src.authz.permissions.catalog import MANAGE_ROLES, VIEW_ROLES

_logger = logging.getLogger(__name__)

roles_router = APIRouter(prefix="/api/v1/workspace/roles", tags=["workspace"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class RoleRequest(BaseModel):
    name: str
    description: str = ""
    permissions: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _role_to_dict(role) -> dict:
    return {
        "id": role.id,
        "name": role.name,
        "description": role.description,
        "permissions": list(role.permissions),
        "isSystem": role.is_system,
        "isLocked": role.is_locked,
        "createdAt": role.created_at,
        "updatedAt": role.updated_at,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@roles_router.get("")
def list_roles(
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(VIEW_ROLES)),
) -> dict:
    try:
        result = _list_roles(info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"roles": [_role_to_dict(r) for r in result]}


@roles_router.get("/{role_id}")
def get_role(
    role_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(VIEW_ROLES)),
) -> dict:
    try:
        role = _get_role(role_id=role_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    if role is None:
        raise HTTPException(status_code=404, detail=f"Role not found: {role_id}")
    return {"role": _role_to_dict(role)}


@roles_router.post("", status_code=201)
def create_role(
    body: RoleRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ROLES)),
) -> dict:
    payload = RoleInput(
        name=body.name,
        description=body.description,
        permissions=list(body.permissions),
    )
    try:
        role = _create_role(input=payload, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"role": _role_to_dict(role)}


@roles_router.patch("/{role_id}")
def update_role(
    role_id: str,
    body: RoleRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ROLES)),
) -> dict:
    payload = RoleInput(
        name=body.name,
        description=body.description,
        permissions=list(body.permissions),
    )
    try:
        role = _update_role(role_id=role_id, input=payload, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"role": _role_to_dict(role)}


@roles_router.delete("/{role_id}")
def delete_role(
    role_id: str,
    replacement_role_id: Optional[str] = None,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ROLES)),
) -> dict:
    try:
        _delete_role(
            role_id=role_id,
            replacement_role_id=replacement_role_id,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}
