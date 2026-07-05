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

from src.db.models import Asset, Grant, TeamMember, User

_ADMIN_ROLES = frozenset({"admin", "owner"})


async def users_with_asset_access(db: AsyncSession, asset_id: str) -> set[str]:
    """Reverse of `get_user_asset_ids`: the set of user ids allowed to read a
    given asset.

    Admins/owners (who see every asset) plus holders of a direct or team grant
    on this asset. Producers use it to avoid telling a user about a finding on
    an asset they can't see.

    Only active accounts are returned: a disabled or deprovisioned user can't
    authenticate to read a notification, so notifying them would just accumulate
    unread items on an account that can never open them.
    """
    from src.authz.roles.service import ADMIN_ROLE_IDS

    admin_stmt = select(User.id).where(User.role_id.in_(ADMIN_ROLE_IDS))
    direct_stmt = select(Grant.subject_id).where(
        Grant.asset_id == asset_id, Grant.subject_type == "user"
    )
    team_stmt = (
        select(TeamMember.user_id)
        .join(Grant, (Grant.subject_type == "team") & (Grant.subject_id == TeamMember.team_id))
        .where(Grant.asset_id == asset_id)
    )
    admins = (await db.execute(admin_stmt)).scalars().all()
    direct = (await db.execute(direct_stmt)).scalars().all()
    team = (await db.execute(team_stmt)).scalars().all()
    candidates = {str(x) for x in [*admins, *direct, *team]}
    if not candidates:
        return set()
    active_stmt = select(User.id).where(User.id.in_(candidates), User.status == "active")
    active = (await db.execute(active_stmt)).scalars().all()
    return {str(x) for x in active}


async def get_user_asset_ids(db: AsyncSession, ctx: dict) -> list[str]:
    """Return asset ids the request is allowed to read.

    Admins/owners see every asset. Other users see assets from team grants
    (teams they belong to) plus any direct user grants.
    Empty list = no access (fail-closed).
    """
    role = ctx.get("role") or "viewer"
    if role in _ADMIN_ROLES:
        rows = (await db.execute(select(Asset.id))).scalars().all()
        return [str(r) for r in rows]

    user_id = ctx.get("user_id")
    if not user_id:
        return []

    # Team-based grants: assets granted to any team the user belongs to
    team_stmt = (
        select(Grant.asset_id)
        .join(TeamMember, (Grant.subject_type == "team") & (Grant.subject_id == TeamMember.team_id))
        .where(TeamMember.user_id == user_id)
    )

    # Direct user grants
    direct_stmt = (
        select(Grant.asset_id)
        .where(Grant.subject_type == "user", Grant.subject_id == user_id)
    )

    team_rows = (await db.execute(team_stmt)).scalars().all()
    direct_rows = (await db.execute(direct_stmt)).scalars().all()
    return list({str(r) for r in [*team_rows, *direct_rows]})




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
