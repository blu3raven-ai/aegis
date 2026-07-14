"""Accepted-risk persistence + the pure scope filter used when building a scan job."""
from __future__ import annotations

from typing import Any

from sqlalchemy import or_, select
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
    # In-scope asset risks PLUS source-wide (asset_id IS NULL) risks — the latter
    # apply to every repo on a source and are managed by manage_sources holders,
    # so a source-wide carve-out must remain listable/manageable (not just applied
    # silently at scan time by matched_for_repo).
    if not asset_ids:
        return []
    rows = (
        await session.execute(
            select(AcceptedRisk).where(
                or_(AcceptedRisk.asset_id.in_(asset_ids), AcceptedRisk.asset_id.is_(None))
            )
        )
    ).scalars().all()
    return [_to_dict(r) for r in rows]


def matched_for_repo(rows: list[dict[str, Any]], *, asset_id: str) -> list[dict[str, Any]]:
    """Enabled risks that apply to this repo: asset-scoped to it, or source-wide
    (asset_id is None). Pure — used when assembling the runner job payload."""
    return [
        r
        for r in rows
        if r.get("enabled") and (r.get("asset_id") in (None, asset_id))
    ]


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
    """Fetch a risk only if its asset is in the caller's scope, or it is source-wide
    (asset_id IS NULL). Returns None (→ 404) when out of scope or unknown."""
    if not asset_ids:
        return None
    return await session.scalar(
        select(AcceptedRisk).where(
            AcceptedRisk.id == risk_id,
            or_(AcceptedRisk.asset_id.in_(asset_ids), AcceptedRisk.asset_id.is_(None)),
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
