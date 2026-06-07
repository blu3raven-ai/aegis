"""Single auth boundary for asset visibility.

`get_user_asset_ids` is the only function that decides which assets a
request may read. Every resolver, route, and service that scopes data must
go through this function (or through `apply_scope` which embeds the IDs in
a query).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, TeamAsset, TeamMember

_ADMIN_ROLES = frozenset({"admin", "owner"})


async def get_user_asset_ids(db: AsyncSession, ctx: dict) -> list[str]:
    """Return asset ids the request is allowed to read.

    Admins/owners see every asset. Other users see assets granted to any team
    they belong to. Empty list = no access (fail-closed).
    """
    role = ctx.get("role") or "viewer"
    if role in _ADMIN_ROLES:
        rows = (await db.execute(select(Asset.id))).scalars().all()
        return [str(r) for r in rows]

    user_id = ctx.get("user_id")
    if not user_id:
        return []

    stmt = (
        select(TeamAsset.asset_id)
        .join(TeamMember, TeamAsset.team_id == TeamMember.team_id)
        .where(TeamMember.user_id == user_id)
        .distinct()
    )
    rows = (await db.execute(stmt)).scalars().all()
    return [str(r) for r in rows]


async def get_user_orgs(db: AsyncSession, ctx: dict) -> list[str]:
    """Return the distinct org strings visible to this user.

    Used by SSE subscribers which still filter events by org name (the event bus
    Event carries `org_id`, not `asset_id`). Derives org strings from Asset rows
    that belong to the user's accessible assets so that the SSE filter correctly
    enforces per-user scope.

    A future event-bus refactor could carry `asset_id` natively and skip the
    org-derivation step entirely; deferred until SSE filtering grows other
    requirements that justify the change.
    """
    asset_ids = await get_user_asset_ids(db, ctx)
    if not asset_ids:
        return []
    # Extract the org segment from external_ref (e.g. "github:owner/repo" -> "owner")
    stmt = (
        select(Asset.external_ref)
        .where(Asset.id.in_(asset_ids))
        .distinct()
    )
    rows = (await db.execute(stmt)).scalars().all()
    orgs: list[str] = []
    for ref in rows:
        if ref and ":" in ref:
            # "github:owner/repo" -> "owner"
            parts = ref.split(":", 1)[1].split("/", 1)
            if parts:
                orgs.append(parts[0])
    return list(dict.fromkeys(orgs))  # deduplicate preserving order


async def resolve_asset_ids_for_org(db: AsyncSession, org: str, *, asset_type: str | None = None) -> list[str]:
    """Map a free-form org name to the asset_ids it owns.

    Used by routers that still accept an `org` body/query param from clients
    (CI, the bulk-review UI, etc.) and need to translate to the scoped
    asset_ids the service layer expects. Matches the org segment of
    canonical external_refs (e.g. "github:acme/foo" or "ghcr:acme/img:tag").
    Optionally filter by asset_type ("repo" or "image").
    """
    if not org:
        return []
    stmt = select(Asset.id).where(Asset.external_ref.like(f"%:{org}/%"))
    if asset_type is not None:
        stmt = stmt.where(Asset.type == asset_type)
    rows = (await db.execute(stmt)).scalars().all()
    return [str(r) for r in rows]


async def resolve_asset_ids_from_request(request) -> list[str]:
    """Resolve the caller's accessible asset_ids from a FastAPI Request.

    Standard pattern for REST routers: extract user_sub + user_role from
    request.state (populated by the auth middleware), open a DB session,
    and call get_user_asset_ids. Centralized here so routers don't each
    roll their own _resolve_asset_ids helper.
    """
    from src.db.engine import async_session_factory

    ctx = {
        "user_id": request.state.user_sub,
        "role": getattr(request.state, "user_role", "viewer"),
    }
    async with async_session_factory() as db:
        return await get_user_asset_ids(db, ctx)


def apply_scope(stmt: Select, asset_ids: list[str], *, column=None) -> Select:
    """Restrict `stmt` to rows whose asset_id is in `asset_ids`.

    Empty list yields a WHERE false predicate — fail-closed. `column`
    defaults to the `asset_id` column of the primary entity; pass it
    explicitly when the column is on a joined table.
    """
    if not asset_ids:
        return stmt.where(sa.false())
    if column is None:
        column = sa.column("asset_id")
    return stmt.where(column.in_(asset_ids))
