"""Workspace team-administration endpoints.

Authorization: MANAGE_ORGANISATIONS. Delegates to
``src.auth.workspace.service`` for the shared business logic.
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from graphql import GraphQLError
from pydantic import BaseModel, field_validator

from src.auth._gql_errors import raise_for_gql
from src.auth.workspace.service import (
    TeamInput,
    WorkspaceMutationResult,
    WorkspaceTeam,
    add_team_member,
    create_team,
    delete_team,
    remove_team_member,
    update_team,
)
from src.authz.enforcement.dependencies import Permission, caller_context
from src.authz.permissions.catalog import MANAGE_ORGANISATIONS
from src.authz.teams.service import list_teams

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/workspace/teams", tags=["workspace"])


# ---------------------------------------------------------------------------
# Pydantic request bodies
# ---------------------------------------------------------------------------

class TeamBody(BaseModel):
    name: str
    description: str = ""

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty")
        return v


class TeamPatchBody(BaseModel):
    """Partial-update body for PATCH — all fields optional."""
    name: Optional[str] = None
    description: Optional[str] = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not v.strip():
            raise ValueError("name must not be empty")
        return v


class AddMemberBody(BaseModel):
    userId: str

    @field_validator("userId")
    @classmethod
    def user_id_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("userId must not be empty")
        return v


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _team_to_response(team: WorkspaceTeam) -> dict[str, Any]:
    """Convert a strawberry WorkspaceTeam to a camelCase JSON-serialisable dict."""
    return {
        "id": str(team.id),
        "name": team.name,
        "description": team.description,
        "source": team.source,
        "members": [
            {"userId": m.user_id, "source": m.source}
            for m in team.members
        ],
        "assets": [
            {
                "assetId": a.asset_id,
                "type": a.type,
                "displayName": a.display_name,
                "externalRef": a.external_ref,
                "source": a.source,
            }
            for a in team.assets
        ],
        "isShared": team.is_shared,
        "createdAt": team.created_at,
        "updatedAt": team.updated_at,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("", status_code=201)
def handle_create_team(
    body: TeamBody,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        team = create_team(
            input=TeamInput(name=body.name, description=body.description),
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _team_to_response(team)


@router.patch("/{team_id}")
def handle_update_team(
    team_id: str,
    body: TeamPatchBody,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    # Fetch current state to fill in fields the caller omitted, so that the
    # resolver (which overwrites every field) produces correct partial updates.
    if body.name is None or body.description is None:
        existing = next((t for t in list_teams() if t["id"] == team_id), None)
        if existing is None:
            raise HTTPException(status_code=404, detail="Team not found.")
        resolved_name = body.name if body.name is not None else existing["name"]
        resolved_description = (
            body.description if body.description is not None else (existing.get("description") or "")
        )
    else:
        resolved_name = body.name
        resolved_description = body.description

    try:
        team = update_team(
            team_id=team_id,
            input=TeamInput(name=resolved_name, description=resolved_description),
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _team_to_response(team)


@router.delete("/{team_id}")
def handle_delete_team(
    team_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        result: WorkspaceMutationResult = delete_team(team_id=team_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": result.ok}


@router.post("/{team_id}/members", status_code=201)
def handle_add_team_member(
    team_id: str,
    body: AddMemberBody,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        team = add_team_member(team_id=team_id, user_id=body.userId, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _team_to_response(team)


@router.delete("/{team_id}/members/{user_id}")
def handle_remove_team_member(
    team_id: str,
    user_id: str,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        team = remove_team_member(team_id=team_id, user_id=user_id, info_context=ctx)
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return _team_to_response(team)
