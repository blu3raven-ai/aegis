from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select

from src.db.helpers import run_db
from src.db.models import Asset, DirectGrant
from src.shared.paths import now_iso as _now_iso


def _grant_to_dict(grant: DirectGrant) -> dict[str, Any]:
    return {
        "userId": grant.user_id,
        "assetId": grant.asset_id,
        "source": grant.source or "manual-direct",
        "createdAt": (
            grant.granted_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if grant.granted_at else _now_iso()
        ),
    }


def user_has_direct_asset_access(grants: list[dict[str, Any]], user_id: str, asset_id: str) -> bool:
    for grant in grants:
        if grant.get("userId") == user_id and grant.get("assetId") == asset_id:
            return True
    return False


def list_direct_grants() -> list[dict[str, Any]]:
    async def _query(session):
        result = await session.execute(select(DirectGrant))
        return [_grant_to_dict(g) for g in result.scalars().all()]

    return run_db(_query)


def add_direct_grant(user_id: str, asset_id: str, source: str = "manual-direct") -> None:
    async def _query(session):
        # Verify the asset exists
        asset_row = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset_row is None:
            raise ValueError(f"Asset {asset_id!r} not found.")

        # Check for existing grant (dedup by user_id + asset_id)
        result = await session.execute(
            select(DirectGrant).where(
                DirectGrant.user_id == user_id,
                DirectGrant.asset_id == asset_id,
            )
        )
        existing = result.scalars().first()
        if existing:
            existing.source = source
        else:
            session.add(DirectGrant(
                id=f"dg_{secrets.token_hex(8)}",
                user_id=user_id,
                asset_id=asset_id,
                # Legacy columns kept nullable; set to sentinel values so DB
                # constraints are satisfied until Task 4 drops the columns.
                resource_type="asset",
                resource_name="",
                source=source,
                granted_at=datetime.now(timezone.utc),
            ))

    run_db(_query)


def remove_direct_grant(user_id: str, asset_id: str) -> None:
    async def _query(session):
        result = await session.execute(
            select(DirectGrant).where(
                DirectGrant.user_id == user_id,
                DirectGrant.asset_id == asset_id,
            )
        )
        for grant in result.scalars().all():
            await session.delete(grant)

    run_db(_query)
