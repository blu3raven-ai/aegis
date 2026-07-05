"""Scan checkpoint utilities for tracking per-asset scan coverage."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, ScanCheckpoint
from src.shared.paths import now_iso


def write_checkpoint(
    tool: str,
    asset_id: str,
    commit_sha: str | None = None,
    scanned_at: str | None = None,
) -> None:
    """Upsert a scan checkpoint for an asset."""
    scanned_at = scanned_at or now_iso()

    async def _query(session: AsyncSession):
        existing = await session.get(ScanCheckpoint, (tool, asset_id))
        if existing:
            existing.last_commit_sha = commit_sha or ""
            existing.last_commit_date = scanned_at
        else:
            session.add(ScanCheckpoint(
                tool=tool,
                asset_id=asset_id,
                last_commit_sha=commit_sha or "",
                last_commit_date=scanned_at,
            ))

    run_db(_query)


def read_checkpoints_for_tool(
    tool: str,
    asset_ids: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """Read checkpoints for a tool, optionally filtered to a set of assets.

    Returns ``{asset_id: {"lastCommitSha", "lastScannedAt"}}``.
    """
    async def _query(session: AsyncSession):
        stmt = select(ScanCheckpoint).where(ScanCheckpoint.tool == tool)
        if asset_ids is not None:
            if not asset_ids:
                return []
            stmt = stmt.where(ScanCheckpoint.asset_id.in_(asset_ids))
        result = await session.execute(stmt)
        return result.scalars().all()

    rows = run_db(_query)
    return {
        cp.asset_id: {
            "lastCommitSha": cp.last_commit_sha,
            "lastScannedAt": cp.last_commit_date,
        }
        for cp in rows
    }


def compute_coverage_gaps(
    tool: str,
    expected_asset_ids: list[str],
    stale_after_days: int = 30,
) -> list[dict[str, Any]]:
    """Return assets that are missing or stale in checkpoints.

    Each gap row carries both ``assetId`` (stable identity) and ``repository``
    (the asset display_name — used by the existing UI to render the gap).
    """
    from datetime import datetime, timezone, timedelta

    if not expected_asset_ids:
        return []

    checkpoints = read_checkpoints_for_tool(tool, expected_asset_ids)

    async def _names(session: AsyncSession):
        result = await session.execute(
            select(Asset.id, Asset.display_name).where(Asset.id.in_(expected_asset_ids))
        )
        return dict(result.all())

    display_by_id: dict[str, str] = run_db(_names)

    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=stale_after_days)
    gaps: list[dict[str, Any]] = []

    for asset_id in expected_asset_ids:
        cp = checkpoints.get(asset_id)
        display = display_by_id.get(asset_id, "")
        if not cp:
            gaps.append({
                "assetId": asset_id,
                "repository": display,
                "reason": "missing_checkpoint",
                "lastScannedAt": None,
            })
            continue
        last_scanned = cp.get("lastScannedAt")
        if last_scanned:
            try:
                scanned_dt = datetime.fromisoformat(last_scanned.replace("Z", "+00:00"))
                if scanned_dt < stale_cutoff:
                    gaps.append({
                        "assetId": asset_id,
                        "repository": display,
                        "reason": "stale",
                        "lastScannedAt": last_scanned,
                    })
            except (ValueError, TypeError):
                gaps.append({
                    "assetId": asset_id,
                    "repository": display,
                    "reason": "stale",
                    "lastScannedAt": last_scanned,
                })

    return gaps
