"""Upsert service for assets — single writer to the `assets` table."""
from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset

AssetType = Literal["repo", "image"]
AssetSource = Literal["source_connection", "manual_upload", "byo_import"]


async def upsert_asset(
    db: AsyncSession,
    *,
    type: AssetType,
    source: AssetSource,
    external_ref: str,
    display_name: str,
    source_ref: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Insert or merge by `external_ref`. Returns the asset id.

    Merge semantics: existing `source` and `source_ref` stick (first-seen wins),
    `display_name` updates, `metadata` is JSONB-merged (existing keys preserved
    unless the new payload overrides them explicitly).
    """
    stmt = insert(Asset).values(
        type=type,
        source=source,
        source_ref=source_ref,
        external_ref=external_ref,
        display_name=display_name,
        asset_metadata=metadata or {},
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["external_ref"],
        set_={
            "display_name": stmt.excluded.display_name,
            Asset.__table__.c.metadata: Asset.__table__.c.metadata.op("||")(stmt.excluded.metadata),
            "updated_at": stmt.excluded.updated_at,
        },
    ).returning(Asset.id)
    asset_id = (await db.execute(stmt)).scalar_one()
    await db.commit()
    return str(asset_id)
