"""Data-retention execution path of the unified rules engine.

For each enabled data_retention rule in an org, evaluate it against the org's
ScanRuns. Two action types:

- archive: flip ScanRun.archived = True (reversible).
- delete: physically delete the ScanRun row (irreversible). Findings are
  preserved (no FK cascade exists between findings and scan_runs).

V1 limitation: archive does NOT cascade to Finding rows. The Finding.archived
column exists for future use but is not set by this evaluator. There is no
reliable FK between findings and scan_runs (findings reference scans only
indirectly via tool/org/identity_key), so a per-finding cascade would
require an unreliable lookup. Documented trade-off; revisit in a later phase
if/when findings gain a direct scan_run_id column.

Concurrency assumption: a single evaluator instance is expected to run per
org at any time (enforced by the cron scheduler). Two concurrent runs over
the same scan_run would double-write the AuditEvent and (for delete actions)
race on row deletion. V1 does not row-lock the candidate set; if the cron is
ever parallelised this evaluator needs SELECT ... FOR UPDATE on the loaded
ScanRun rows.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from src.audit_log.recorder import ActorInfo, get_recorder
from src.db.helpers import run_db
from src.db.models import Rule, ScanRun
from src.rules.scan_result_subject_loader import build_scan_result_subject
from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import get_scan_result_field
from src.shared.archived_filter import exclude_archived


logger = logging.getLogger(__name__)

# Coarse prefilter: schema enforces after_days >= 30 for archive (and >= 90
# for delete), so a ScanRun finished less than 30 days ago cannot satisfy
# any well-formed data_retention rule. Skip them at the query level so we
# don't load every recent ScanRun into memory.
_MIN_ACTION_AGE_DAYS = 30


@dataclass
class DataRetentionEvalResult:
    rules_evaluated: int
    scans_checked: int
    archived: int
    deleted: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def evaluate_data_retention(
    *, asset_ids: list[str], now: datetime | None = None
) -> DataRetentionEvalResult:
    """Evaluate every enabled data_retention rule against scan runs scoped to asset_ids."""
    if not asset_ids:
        return DataRetentionEvalResult(0, 0, 0, 0)

    current_time = _ensure_aware(now) if now is not None else _utcnow()
    prefilter_cutoff = current_time - timedelta(days=_MIN_ACTION_AGE_DAYS)

    async def _evaluate(session) -> DataRetentionEvalResult:
        rules_q = await session.execute(
            select(Rule).where(
                Rule.category == "data_retention",
                Rule.enabled == True,  # noqa: E712
            )
        )
        rules = list(rules_q.scalars().all())
        if not rules:
            return DataRetentionEvalResult(0, 0, 0, 0)

        scans_stmt = exclude_archived(
            select(ScanRun).where(
                ScanRun.asset_id.in_(asset_ids),
                ScanRun.status == "completed",
                ScanRun.finished_at.is_not(None),
                ScanRun.finished_at <= prefilter_cutoff,
            ),
            ScanRun,
        ).order_by(ScanRun.finished_at.asc())

        scans_q = await session.execute(scans_stmt)
        scans = list(scans_q.scalars().all())

        archived = 0
        deleted = 0

        for run in scans:
            subject = build_scan_result_subject(run, now=current_time)
            for rule in rules:
                try:
                    matched = evaluate_condition(
                        rule.conditions or {}, subject, get_scan_result_field
                    )
                except Exception:
                    logger.exception(
                        "data_retention evaluator: rule %s conditions failed for scan %s",
                        rule.id, run.id,
                    )
                    continue
                if not matched:
                    continue

                action = rule.action or {}
                action_type = action.get("type")
                after_days = action.get("after_days")
                if not isinstance(after_days, int) or after_days <= 0:
                    logger.warning(
                        "data_retention evaluator: rule %s has invalid after_days=%r; skipping",
                        rule.id, after_days,
                    )
                    continue
                if subject.age_days < after_days:
                    continue

                if action_type == "archive":
                    _archive_scan_run(session, run, rule.id, current_time)
                    archived += 1
                    break
                if action_type == "delete":
                    await _delete_scan_run(session, run, rule.id, current_time)
                    deleted += 1
                    break
                logger.warning(
                    "data_retention evaluator: rule %s has unknown action.type=%r; skipping",
                    rule.id, action_type,
                )

        for rule in rules:
            rule.last_evaluated_at = current_time

        return DataRetentionEvalResult(
            rules_evaluated=len(rules),
            scans_checked=len(scans),
            archived=archived,
            deleted=deleted,
        )

    return run_db(_evaluate)


def _archive_scan_run(session, run: ScanRun, rule_id: str, now: datetime) -> None:
    """Flip archived flag on the scan run. Reversible.

    Does not cascade to findings (no FK exists between findings and scan_runs;
    cascading would require an unreliable denormalised lookup in V1).
    """
    run.archived = True
    run.archived_at = now
    run.archived_by_rule_id = rule_id

    # record_in_session() instead of record() — we're inside an async session,
    # and record() would deadlock by nesting another run_db(). Same on delete.
    get_recorder().record_in_session(
        session,
        action="rule.data_retention.archived",
        resource_type="scan_run",
        resource_id=str(run.id),
        actor=ActorInfo(username=f"auto-rule:{rule_id}", role="system"),
        metadata={"rule_id": rule_id, "tool": run.tool},
    )


async def _delete_scan_run(session, run: ScanRun, rule_id: str, now: datetime) -> None:
    """Physically delete the scan run row. Irreversible.

    Audit log is written BEFORE the delete inside the same session so the
    trace survives in the same transaction.
    """
    get_recorder().record_in_session(
        session,
        action="rule.data_retention.deleted",
        resource_type="scan_run",
        resource_id=str(run.id),
        actor=ActorInfo(username=f"auto-rule:{rule_id}", role="system"),
        metadata={
            "rule_id": rule_id,
            "tool": run.tool,
            "deleted_at": now.isoformat(),
        },
    )
    # Findings are intentionally preserved — no FK cascade exists between
    # findings and scan_runs (documented V1 trade-off).
    await session.delete(run)


__all__ = [
    "DataRetentionEvalResult",
    "evaluate_data_retention",
]
