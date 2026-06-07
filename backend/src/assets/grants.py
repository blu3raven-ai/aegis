"""Auto-grant helpers for manual / BYO upload paths."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import TeamAsset, TeamMember


async def primary_team_id_for_user(db: AsyncSession, user_id: str) -> str | None:
    """Return the team id with the oldest membership for this user.

    Used as the auto-grant target for manual / BYO uploads. Tiebreaker on
    team_id ASC for deterministic behavior.
    """
    stmt = (
        select(TeamMember.team_id)
        .where(TeamMember.user_id == user_id)
        .order_by(TeamMember.added_at.asc(), TeamMember.team_id.asc())
        .limit(1)
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def auto_grant_to_uploader(
    db: AsyncSession, *, asset_id: str, user_id: str,
) -> None:
    """Grant the asset to the uploader's primary team.

    Idempotent: re-granting an existing (team, asset) pair is a no-op via
    ON CONFLICT. Raises ValueError if the user has no team membership.
    """
    team_id = await primary_team_id_for_user(db, user_id)
    if team_id is None:
        raise ValueError("user has no team membership; cannot auto-grant")
    stmt = insert(TeamAsset).values(team_id=team_id, asset_id=asset_id, source="upload")
    stmt = stmt.on_conflict_do_nothing(index_elements=["team_id", "asset_id"])
    await db.execute(stmt)
    await db.commit()
