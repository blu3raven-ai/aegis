"""Upsert service for assets — single writer to the `assets` table."""
from __future__ import annotations

from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset

AssetType = Literal["repo", "image"]
AssetSource = Literal["source_connection", "manual_upload", "byo_import"]


def resolve_repo_asset_ids(repo_full_names: list[str]) -> dict[str, str]:
    """Bulk-resolve "owner/name" repo display names to asset_ids.

    Looks up assets of type 'repo' whose ``display_name`` matches. Repos that
    have no asset row (e.g. discovered by a source connection but never synced)
    are omitted from the result. Mirrors the dedup behaviour of
    ``build_source_repo_list`` — if multiple repo assets share a display_name
    (rare across source types), the result picks one arbitrarily.
    """
    if not repo_full_names:
        return {}

    names = [n for n in repo_full_names if isinstance(n, str) and "/" in n]
    if not names:
        return {}

    async def _query(db: AsyncSession) -> list[tuple[str, str]]:
        result = await db.execute(
            select(Asset.display_name, Asset.id).where(
                Asset.type == "repo",
                Asset.display_name.in_(names),
            )
        )
        return [(name, asset_id) for name, asset_id in result.all()]

    return {name: asset_id for name, asset_id in run_db(_query)}


def get_all_asset_ids() -> list[str]:
    """Every asset id in the system.

    System-wide nightly/hourly recomputes (e.g. SLA breach status) operate over
    all findings, so they need every asset id — not the org names that drive the
    per-source scan-rerun triggers. ``Finding.asset_id`` is the Asset PK, so the
    recompute's ``asset_id IN (...)`` filter only matches when fed these ids.
    """
    async def _query(db: AsyncSession) -> list[str]:
        result = await db.execute(select(Asset.id))
        return [str(row[0]) for row in result.all()]

    return run_db(_query)


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
