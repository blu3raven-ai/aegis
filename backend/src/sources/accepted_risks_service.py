"""Accepted-risk persistence + the pure scope filter used when building a scan job."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import AcceptedRisk


def _to_dict(r: AcceptedRisk) -> dict[str, Any]:
    return {
        "id": r.id,
        "asset_id": r.asset_id,
        "source_connection_id": r.source_connection_id,
        "statement": r.statement,
        "path_glob": r.path_glob,
        "rule_id": r.rule_id,
        "scanner": r.scanner,
        "enabled": r.enabled,
        "created_by": r.created_by,
    }


async def list_for_assets(session: AsyncSession, asset_ids: list[str]) -> list[dict[str, Any]]:
    # Strictly asset-scoped. A carve-out only ever affects the specific asset it
    # targets — the data model has no reliable asset→source link, so there is no
    # safe "source-wide" query (a null-asset row would suppress findings on every
    # source). Every risk MUST carry an asset_id in the caller's scope.
    if not asset_ids:
        return []
    rows = (
        await session.execute(select(AcceptedRisk).where(AcceptedRisk.asset_id.in_(asset_ids)))
    ).scalars().all()
    return [_to_dict(r) for r in rows]


def matched_for_repo(rows: list[dict[str, Any]], *, asset_id: str) -> list[dict[str, Any]]:
    """Enabled risks that target exactly this asset. Pure — used when assembling
    the runner job payload. Only the asset's OWN risks apply; a risk never leaks
    onto a different asset (or source)."""
    return [r for r in rows if r.get("enabled") and r.get("asset_id") == asset_id]


async def create(
    session: AsyncSession, data: dict[str, Any], *, created_by: str | None
) -> dict[str, Any]:
    row = AcceptedRisk(
        asset_id=data.get("asset_id"),
        source_connection_id=data.get("source_connection_id"),
        statement=data["statement"],
        path_glob=data.get("path_glob"),
        rule_id=data.get("rule_id"),
        scanner=data.get("scanner"),
        enabled=data.get("enabled", True),
        created_by=created_by,
    )
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return _to_dict(row)


async def get_scoped(
    session: AsyncSession, risk_id: int, asset_ids: list[str]
) -> AcceptedRisk | None:
    """Fetch a risk only if its asset is in the caller's scope. Returns None (→ 404)
    when out of scope or unknown."""
    if not asset_ids:
        return None
    return await session.scalar(
        select(AcceptedRisk).where(
            AcceptedRisk.id == risk_id,
            AcceptedRisk.asset_id.in_(asset_ids),
        )
    )


async def update_fields(
    session: AsyncSession, row: AcceptedRisk, patch: dict[str, Any]
) -> dict[str, Any]:
    for key in ("statement", "path_glob", "rule_id", "scanner", "enabled"):
        if key in patch and patch[key] is not None:
            setattr(row, key, patch[key])
    await session.commit()
    await session.refresh(row)
    return _to_dict(row)


async def delete(session: AsyncSession, row: AcceptedRisk) -> None:
    await session.delete(row)
    await session.commit()
