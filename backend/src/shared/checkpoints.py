"""Scan checkpoint utilities for tracking per-repo scan coverage."""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import ScanCheckpoint
from src.shared.paths import now_iso


def write_checkpoint(
    tool: str,
    org: str,
    repo: str,
    commit_sha: str | None = None,
    scanned_at: str | None = None,
) -> None:
    """Upsert a scan checkpoint for a repo."""
    scanned_at = scanned_at or now_iso()

    async def _query(session: AsyncSession):
        result = await session.execute(
            select(ScanCheckpoint).where(
                ScanCheckpoint.tool == tool,
                ScanCheckpoint.org == org.lower(),
                ScanCheckpoint.repo == repo,
            )
        )
        existing = result.scalars().first()
        if existing:
            existing.last_commit_sha = commit_sha or ""
            existing.last_commit_date = scanned_at
        else:
            session.add(ScanCheckpoint(
                tool=tool,
                org=org.lower(),
                repo=repo,
                last_commit_sha=commit_sha or "",
                last_commit_date=scanned_at,
            ))

    run_db(_query)


def read_checkpoints_for_tool(tool: str, org: str | None = None) -> dict[str, dict[str, Any]]:
    """Read all checkpoints for a tool, optionally filtered by org."""
    async def _query(session: AsyncSession):
        stmt = select(ScanCheckpoint).where(ScanCheckpoint.tool == tool)
        if org:
            stmt = stmt.where(ScanCheckpoint.org == org.lower())
        result = await session.execute(stmt)
        return {
            cp.repo: {
                "lastCommitSha": cp.last_commit_sha,
                "lastScannedAt": cp.last_commit_date,
            }
            for cp in result.scalars().all()
        }

    return run_db(_query)


def compute_coverage_gaps(
    tool: str,
    org: str,
    expected_repos: list[str],
    stale_after_days: int = 30,
) -> list[dict[str, Any]]:
    """Return repos that are missing or stale in checkpoints."""
    from datetime import datetime, timezone, timedelta

    checkpoints = read_checkpoints_for_tool(tool, org)
    now = datetime.now(timezone.utc)
    stale_cutoff = now - timedelta(days=stale_after_days)
    gaps: list[dict[str, Any]] = []

    for repo in expected_repos:
        cp = checkpoints.get(repo)
        if not cp:
            gaps.append({"repository": repo, "reason": "missing_checkpoint", "lastScannedAt": None})
            continue
        last_scanned = cp.get("lastScannedAt")
        if last_scanned:
            try:
                scanned_dt = datetime.fromisoformat(last_scanned.replace("Z", "+00:00"))
                if scanned_dt < stale_cutoff:
                    gaps.append({"repository": repo, "reason": "stale", "lastScannedAt": last_scanned})
            except (ValueError, TypeError):
                gaps.append({"repository": repo, "reason": "stale", "lastScannedAt": last_scanned})

    return gaps
