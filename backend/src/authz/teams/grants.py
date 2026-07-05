from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import Asset, Grant
from src.shared.paths import now_iso as _now_iso


def _grant_to_dict(grant: Grant, asset: Asset | None = None) -> dict[str, Any]:
    base: dict[str, Any] = {
        "subjectType": grant.subject_type,
        "subjectId": grant.subject_id,
        "assetId": grant.asset_id,
        "source": grant.source or "manual",
        "createdAt": (
            grant.created_at.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            if grant.created_at else _now_iso()
        ),
    }
    if asset is not None:
        base["assetType"] = asset.type
        base["assetDisplayName"] = asset.display_name
        base["assetExternalRef"] = asset.external_ref
    return base


def list_grants(
    *,
    subject_type: str | None = None,
    subject_id: str | None = None,
    asset_id: str | None = None,
) -> list[dict[str, Any]]:
    async def _query(session):
        stmt = select(Grant, Asset).join(Asset, Grant.asset_id == Asset.id)
        if subject_type is not None:
            stmt = stmt.where(Grant.subject_type == subject_type)
        if subject_id is not None:
            stmt = stmt.where(Grant.subject_id == subject_id)
        if asset_id is not None:
            stmt = stmt.where(Grant.asset_id == asset_id)
        rows = (await session.execute(stmt)).all()
        return [_grant_to_dict(grant, asset) for grant, asset in rows]

    return run_db(_query)


def add_grant(
    *,
    subject_type: str,
    subject_id: str,
    asset_id: str,
    source: str = "manual",
) -> None:
    if subject_type not in ("user", "team"):
        raise ValueError(f"Invalid subject_type: {subject_type!r}")

    async def _query(session):
        asset_row = (await session.execute(
            select(Asset).where(Asset.id == asset_id)
        )).scalar_one_or_none()
        if asset_row is None:
            raise ValueError(f"Asset {asset_id!r} not found.")

        stmt = pg_insert(Grant).values(
            subject_type=subject_type,
            subject_id=subject_id,
            asset_id=asset_id,
            source=source,
            created_at=datetime.now(timezone.utc),
        ).on_conflict_do_update(
            index_elements=["subject_type", "subject_id", "asset_id"],
            set_={"source": source},
        )
        await session.execute(stmt)

    run_db(_query)


def remove_grant(*, subject_type: str, subject_id: str, asset_id: str) -> None:
    async def _query(session):
        await session.execute(
            delete(Grant).where(
                Grant.subject_type == subject_type,
                Grant.subject_id == subject_id,
                Grant.asset_id == asset_id,
            )
        )

    run_db(_query)
