"""Loader: builds a RuleRepoSubject from an Asset row for the scanner-coverage evaluator."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, ScanRun
from src.rules_engine.subjects import RuleRepoSubject


# Mirrored from src.sources.service to avoid importing the async-heavy sources
# service module here; if this list drifts, scanner coverage will silently
# diverge from the sources page.
_SCANNER_TYPES = ("dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning")


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def load_repo_subject(
    asset: Asset, session: AsyncSession, *, now: datetime
) -> RuleRepoSubject:
    """Build a fully-hydrated RuleRepoSubject for evaluator use.

    ``now`` is required so the evaluator drives a single deterministic clock
    across every subject in a run — `last_scan_age_days` is derived from it.
    """
    # Scanner coverage: most-recent completed ScanRun per tool for this asset.
    rows = (
        await session.execute(
            select(ScanRun.tool, func.max(ScanRun.finished_at))
            .where(
                ScanRun.asset_id == asset.id,
                ScanRun.status == "completed",
                ScanRun.tool.in_(_SCANNER_TYPES),
                ScanRun.finished_at.isnot(None),
            )
            .group_by(ScanRun.tool)
        )
    ).all()
    tool_to_finished = {tool: finished for tool, finished in rows}

    scanners_with_coverage = [t for t in _SCANNER_TYPES if t in tool_to_finished]
    last_scanned_at = max(tool_to_finished.values()) if tool_to_finished else None

    if last_scanned_at is None:
        last_scan_age_days: int | None = None
    else:
        last_scan_age_days = (_ensure_aware(now) - _ensure_aware(last_scanned_at)).days

    # repo_id is the human-readable display_name (e.g. "acme/foo"); UI rules
    # reference repos by display, not UUID.
    repo_id = asset.display_name or str(asset.id)
    return RuleRepoSubject(
        repo_id=repo_id,
        repo_labels=asset.labels or [],
        tier=asset.tier,
        archived=asset.archived,
        scanners_with_coverage=scanners_with_coverage,
        image_registry=asset.image_registry,
        last_scanned_at=last_scanned_at,
        last_scan_age_days=last_scan_age_days,
    )


__all__ = ["load_repo_subject"]
