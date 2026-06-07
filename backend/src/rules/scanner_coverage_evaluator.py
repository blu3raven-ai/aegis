"""Scanner-coverage execution path of the unified rules engine.

For each enabled scanner_coverage rule in an org, evaluate it against the
org's non-archived Repos and upsert RuleViolation rows. Two action types:

- require_scanners: open a violation per repo missing any required scanner
  in ``action.required_scanners``; resolve when coverage is added.
- stale_alert: open a violation when ``last_scan_age_days > stale_after_days``
  and dispatch a one-time stale alert event. Optionally publish a re-scan
  event if ``action.auto_retrigger`` is true.

The evaluator publishes events (``rule.scanner_coverage.stale_alert``,
``rule.scanner_coverage.retrigger_scan``) onto the event bus; actual
notification delivery and scan enqueueing happen in downstream listeners.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import Repo, Rule, RuleViolation
from src.rules.repo_subject_loader import load_repo_subject
from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import get_repo_field


logger = logging.getLogger(__name__)


@dataclass
class ScannerCoverageEvalResult:
    rules_evaluated: int
    repos_checked: int
    violations_opened: int
    violations_resolved: int
    stale_alerts_dispatched: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _empty_scanner_coverage_result() -> ScannerCoverageEvalResult:
    return ScannerCoverageEvalResult(0, 0, 0, 0, 0)


def evaluate_scanner_coverage_for_org(
    org_id: str | None = None,
    *,
    asset_ids: list[str] | None = None,
    now: datetime | None = None,
) -> ScannerCoverageEvalResult:
    """Evaluate every enabled scanner_coverage rule against the org's repos.

    Pass ``asset_ids`` to scope by asset identity rather than org string.
    An empty ``asset_ids`` list returns an empty result immediately.
    """
    if asset_ids is not None and not asset_ids:
        return _empty_scanner_coverage_result()

    current_time = _ensure_aware(now) if now is not None else _utcnow()

    async def _evaluate(session) -> ScannerCoverageEvalResult:
        rules_q = await session.execute(
            select(Rule).where(
                Rule.category == "scanner_coverage",
                Rule.enabled == True,  # noqa: E712
                Rule.org_id == org_id,
            )
        )
        rules = list(rules_q.scalars().all())
        if not rules:
            return _empty_scanner_coverage_result()

        if asset_ids is not None:
            repos_q = await session.execute(
                select(Repo).where(
                    Repo.asset_id.in_(asset_ids),
                    Repo.archived == False,  # noqa: E712
                )
            )
        else:
            # Unscoped evaluator runs cover every non-archived repo on the
            # instance — used for global rule evaluation; per-scope runs go
            # through the asset_ids branch above.
            repos_q = await session.execute(
                select(Repo).where(Repo.archived == False)  # noqa: E712
            )
        repos = list(repos_q.scalars().all())

        subjects = [
            (repo, await load_repo_subject(repo, session, now=current_time))
            for repo in repos
        ]

        opened = 0
        resolved = 0
        stale_alerts = 0

        for rule in rules:
            action = rule.action or {}
            action_type = action.get("type")

            for repo, subject in subjects:
                repo_subject_id = subject.repo_id

                try:
                    matched = evaluate_condition(
                        rule.conditions or {}, subject, get_repo_field
                    )
                except Exception:
                    logger.exception(
                        "Scanner-coverage evaluator: rule %s conditions failed for repo %s",
                        rule.id, repo_subject_id,
                    )
                    continue

                if not matched:
                    if await _resolve_open_violation(
                        session=session,
                        rule_id=rule.id,
                        repo_id=repo_subject_id,
                        current_time=current_time,
                    ):
                        resolved += 1
                    continue

                if action_type == "require_scanners":
                    required = action.get("required_scanners") or []
                    missing = sorted(set(required) - set(subject.scanners_with_coverage))
                    if missing:
                        if await _upsert_open_violation(
                            session=session,
                            rule_id=rule.id,
                            repo_id=repo_subject_id,
                            context={"missing_scanners": missing},
                            current_time=current_time,
                        ):
                            opened += 1
                    else:
                        if await _resolve_open_violation(
                            session=session,
                            rule_id=rule.id,
                            repo_id=repo_subject_id,
                            current_time=current_time,
                        ):
                            resolved += 1

                elif action_type == "stale_alert":
                    stale_after = action.get("stale_after_days")
                    age = subject.last_scan_age_days
                    if (
                        isinstance(stale_after, int)
                        and age is not None
                        and age > stale_after
                    ):
                        freshly_opened = await _upsert_open_violation(
                            session=session,
                            rule_id=rule.id,
                            repo_id=repo_subject_id,
                            context={"last_scan_age_days": age},
                            current_time=current_time,
                        )
                        if freshly_opened:
                            opened += 1
                            _dispatch_stale_alert(
                                org_id=org_id,
                                rule=rule,
                                repo_id=repo_subject_id,
                                action=action,
                                subject_last_scan_age_days=age,
                            )
                            stale_alerts += 1
                    else:
                        if await _resolve_open_violation(
                            session=session,
                            rule_id=rule.id,
                            repo_id=repo_subject_id,
                            current_time=current_time,
                        ):
                            resolved += 1

                else:
                    logger.warning(
                        "Scanner-coverage evaluator: rule %s has unknown action.type=%r; skipping",
                        rule.id, action_type,
                    )

        for rule in rules:
            rule.last_evaluated_at = current_time

        return ScannerCoverageEvalResult(
            rules_evaluated=len(rules),
            repos_checked=len(repos),
            violations_opened=opened,
            violations_resolved=resolved,
            stale_alerts_dispatched=stale_alerts,
        )

    return run_db(_evaluate)


async def _upsert_open_violation(
    *,
    session,
    rule_id: str,
    repo_id: str,
    context: dict,
    current_time: datetime,
) -> bool:
    """Insert an open violation if not already open. Return True iff freshly inserted."""
    insert_stmt = (
        pg_insert(RuleViolation)
        .values(
            rule_id=rule_id,
            subject_type="repo",
            subject_id=repo_id,
            status="open",
            opened_at=current_time,
            context=context,
        )
        .on_conflict_do_nothing(
            index_elements=["rule_id", "subject_type", "subject_id"],
            index_where=sa.text("status = 'open'"),
        )
        .returning(RuleViolation.id)
    )
    result = await session.execute(insert_stmt)
    return result.scalar_one_or_none() is not None


async def _resolve_open_violation(
    *,
    session,
    rule_id: str,
    repo_id: str,
    current_time: datetime,
) -> bool:
    """Resolve any open violation for (rule_id, repo_id). Return True iff one was resolved."""
    open_q = await session.execute(
        select(RuleViolation).where(
            RuleViolation.rule_id == rule_id,
            RuleViolation.subject_type == "repo",
            RuleViolation.subject_id == repo_id,
            RuleViolation.status == "open",
        )
    )
    violation = open_q.scalar_one_or_none()
    if violation is None:
        return False
    violation.status = "resolved"
    violation.resolved_at = current_time
    return True


def _dispatch_stale_alert(
    *,
    org_id: str,
    rule: Rule,
    repo_id: str,
    action: dict,
    subject_last_scan_age_days: int | None,
) -> None:
    """Publish the stale-alert event + optionally publish retrigger-scan."""
    from src.shared.event_bus import Event, get_event_bus

    bus = get_event_bus()
    bus.publish_sync(Event(
        event_type="rule.scanner_coverage.stale_alert",
        org=org_id,
        data={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "repo_id": repo_id,
            "last_scan_age_days": subject_last_scan_age_days,
            "channel_id": action.get("alert_channel_id"),
        },
    ))
    if action.get("auto_retrigger"):
        bus.publish_sync(Event(
            event_type="rule.scanner_coverage.retrigger_scan",
            org=org_id,
            data={
                "rule_id": rule.id,
                "repo_id": repo_id,
                "source": "rule.stale_alert",
            },
        ))
    logger.info(
        "Scanner-coverage stale alert dispatched: rule=%s repo=%s org=%s auto_retrigger=%s",
        rule.id, repo_id, org_id, bool(action.get("auto_retrigger")),
    )


__all__ = [
    "ScannerCoverageEvalResult",
    "evaluate_scanner_coverage_for_org",
]
