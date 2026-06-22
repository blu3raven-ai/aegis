"""Workspace grant-administration endpoints.

Lives next to auth/workspace/roles_router on the auth REST surface — both
manage workspace authorisation. Delegates to ``src.auth.workspace.service``
for the shared business logic.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from graphql import GraphQLError
from pydantic import BaseModel

from src.auth._gql_errors import raise_for_gql
from src.auth.workspace.service import (
    add_grant_mutation as _add_grant,
    grants as _list_grants,
    remove_grant_mutation as _remove_grant,
)
from src.authz.enforcement.dependencies import Permission, caller_context
from src.authz.permissions.catalog import MANAGE_ORGANISATIONS

_logger = logging.getLogger(__name__)

grants_router = APIRouter(prefix="/api/v1/workspace/grants", tags=["workspace"])


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class AddGrantRequest(BaseModel):
    subject_type: str
    subject_id: str
    asset_id: str
    source: str = "manual"


class RemoveGrantRequest(BaseModel):
    subject_type: str
    subject_id: str
    asset_id: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _grant_to_dict(grant) -> dict:
    return {
        "subjectType": grant.subject_type,
        "subjectId": grant.subject_id,
        "assetId": grant.asset_id,
        "assetType": grant.asset_type,
        "assetDisplayName": grant.asset_display_name,
        "assetExternalRef": grant.asset_external_ref,
        "source": grant.source,
        "createdAt": grant.created_at,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@grants_router.get("")
def list_grants(
    subject_type: Optional[str] = Query(default=None),
    subject_id: Optional[str] = Query(default=None),
    asset_id: Optional[str] = Query(default=None),
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        result = _list_grants(
            subject_type=subject_type,
            subject_id=subject_id,
            asset_id=asset_id,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"grants": [_grant_to_dict(g) for g in result]}


@grants_router.post("", status_code=201)
def add_grant(
    body: AddGrantRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        _add_grant(
            subject_type=body.subject_type,
            subject_id=body.subject_id,
            asset_id=body.asset_id,
            source=body.source,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}


@grants_router.delete("")
def remove_grant(
    body: RemoveGrantRequest,
    ctx: dict = Depends(caller_context),
    _: None = Depends(Permission(MANAGE_ORGANISATIONS)),
) -> dict:
    try:
        _remove_grant(
            subject_type=body.subject_type,
            subject_id=body.subject_id,
            asset_id=body.asset_id,
            info_context=ctx,
        )
    except GraphQLError as e:
        raise_for_gql(e, logger=_logger)
    return {"ok": True}
