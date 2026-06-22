"""GraphQL resolver for the SCIM settings surface."""
from __future__ import annotations

from typing import Optional

import strawberry
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.authz.enforcement import has_permission
from src.authz.permissions.catalog import MANAGE_SETTINGS
from src.db.helpers import run_db
from src.db.models import ScimConfig
from src.graphql.resolver_utils import raise_permission_denied, raise_unauthenticated


@strawberry.type
class ScimSettings:
    enabled: bool
    default_role_id: Optional[str]
    token_set: bool
    scim_endpoint_url: str
    updated_at: Optional[str]


def _gate(info_context: dict):
    request = info_context.get("request") if info_context else None
    if request is None:
        raise_unauthenticated()
    if not has_permission(request, MANAGE_SETTINGS):
        raise_permission_denied("Permission denied: manage_settings")
    return request


def _origin(request) -> str:
    scheme = request.url.scheme
    host = request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}"


async def _get_scim_singleton(session) -> ScimConfig:
    await session.execute(
        pg_insert(ScimConfig).values(id=1).on_conflict_do_nothing(index_elements=["id"])
    )
    return (await session.execute(select(ScimConfig).where(ScimConfig.id == 1))).scalar_one()


def scim_settings(*, info_context: dict) -> ScimSettings:
    request = _gate(info_context)
    endpoint = f"{_origin(request)}/scim/v2/"

    async def _q(session):
        row = await _get_scim_singleton(session)
        return ScimSettings(
            enabled=row.enabled,
            default_role_id=row.default_role_id,
            token_set=row.token_hash is not None,
            scim_endpoint_url=endpoint,
            updated_at=row.updated_at.isoformat() if row.updated_at else None,
        )

    return run_db(_q)
