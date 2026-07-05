"""Loader: builds a RuleScanResultSubject from a ScanRun row.

Used by the data-retention evaluator. The subject is a flat view over the
fields the rules engine is allowed to predicate on (see ``RuleScanResultSubject``
field allowlist in src.rules_engine.subjects).
"""
from __future__ import annotations

from datetime import datetime, timezone

from src.db.models import ScanRun
from src.rules_engine.subjects import RuleScanResultSubject


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def build_scan_result_subject(run: ScanRun, *, now: datetime) -> RuleScanResultSubject:
    """Convert a ScanRun row to a rules-engine subject.

    ``repo_id`` is read from the scan_run's metadata JSON under the key
    ``repo_id``; if absent, an empty string is used and any condition
    predicating on repo_id won't match.

    ``age_days`` is computed from ``finished_at`` against ``now``; 0 if
    ``finished_at`` is missing (no useful age signal for unfinished runs).
    """
    finished_at = run.finished_at
    if finished_at is None:
        age_days = 0
    else:
        finished_at_aware = _ensure_aware(finished_at)
        age_days = max(0, (_ensure_aware(now) - finished_at_aware).days)

    metadata = run.metadata_json or {}
    repo_id = metadata.get("repo_id") or ""

    return RuleScanResultSubject(
        scan_id=str(run.id),
        repo_id=repo_id,
        tool=run.tool or "",
        finished_at=run.finished_at,
        age_days=age_days,
    )


__all__ = ["build_scan_result_subject"]
