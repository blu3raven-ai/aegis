"""Loader: builds a RuleRepoSubject from a Repo row for the scanner-coverage evaluator."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Repo, ScanRun
from src.rules_engine.subjects import RuleRepoSubject


# Mirrored from src.repos.service to avoid importing the async-heavy repos
# service module here; if this list drifts, scanner coverage will silently
# diverge from the repos page.
_SCANNER_TYPES = ("dependencies", "code_scanning", "container_scanning", "secrets")


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


async def load_repo_subject(
    repo_row: Repo, session: AsyncSession, *, now: datetime
) -> RuleRepoSubject:
    """Build a fully-hydrated RuleRepoSubject for evaluator use.

    Scanner coverage is computed at the org level (mirroring repos/service.py),
    not per-repo, because ScanRun does not carry a reliable repo_id.

    ``now`` is required so the evaluator drives a single deterministic clock
    across every subject in a run — `last_scan_age_days` is derived from it.
    """
    # Scanner coverage: most-recent completed ScanRun per tool for this asset.
    tool_to_finished: dict[str, datetime] = {}
    if repo_row.asset_id is not None:
        rows = (
            await session.execute(
                select(ScanRun.tool, func.max(ScanRun.finished_at))
                .where(
                    ScanRun.asset_id == repo_row.asset_id,
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
    # reference repos by display, not UUID. Asset row is looked up alongside
    # so it can be unset gracefully if the FK ever drifts.
    repo_id = ""
    if repo_row.asset_id is not None:
        asset = await session.get(Asset, repo_row.asset_id)
        if asset is not None:
            repo_id = asset.display_name or str(repo_row.asset_id)
    return RuleRepoSubject(
        repo_id=repo_id,
        repo_labels=repo_row.labels or [],
        tier=repo_row.tier,
        archived=repo_row.archived,
        scanners_with_coverage=scanners_with_coverage,
        image_registry=repo_row.image_registry,
        last_scanned_at=last_scanned_at,
        last_scan_age_days=last_scan_age_days,
    )


__all__ = ["load_repo_subject"]
