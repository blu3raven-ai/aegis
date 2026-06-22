"""SLA-category execution path of the unified rules engine.

This module owns three responsibilities:

1. For each enabled SLA-category rule in an org, evaluate it against the org's
   active Findings and upsert ``RuleViolation`` rows (open on match, resolve
   when the finding closes).
2. Dual-write to the legacy ``FindingSlaStatus`` table so existing dashboards
   and queries keep working. This dual-write is time-bounded — to be removed
   in P1.5 once consumers have migrated to ``RuleViolation``.
3. Fire escalation notifications for open violations whose ``at_hours``
   threshold has elapsed, tracking fired thresholds in
   ``RuleViolation.context['escalation_state']`` to keep escalations
   idempotent.

The evaluator is intentionally decoupled from the notification senders: it
publishes an ``sla.escalation`` event onto the shared event bus and lets the
existing notification routing pick it up.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import (
    Finding,
    FindingSlaStatus,
    NotificationDestination,
    Rule,
    RuleViolation,
)
from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import RuleFindingSubject, get_finding_field


logger = logging.getLogger(__name__)


_CLOSED_STATES = ("fixed", "dismissed")


@dataclass
class SlaEvaluationResult:
    rules_evaluated: int
    findings_checked: int
    violations_opened: int
    violations_resolved: int
    escalations_fired: int


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _finding_to_subject(finding: Finding, *, age_days: int) -> RuleFindingSubject:
    """Build a P1 subject from a Finding row.

    Fields that require joins (kev_matched, repo_labels, repo_archived, etc.)
    are populated by later phases — P1 leaves them at safe defaults so any
    rule that predicates on them simply won't match.
    """
    return RuleFindingSubject(
        finding_id=finding.id,
        severity=(finding.severity or "").lower(),
        scanner=finding.tool or "",
        repo_id=finding.repo or "",
        repo_labels=[],
        repo_archived=False,
        cve_id=finding.cve_id,
        cwe_id=None,
        kev_matched=False,
        epss_score=None,
        file_path=finding.file_path,
        age_days=age_days,
    )


def _empty_sla_result() -> SlaEvaluationResult:
    return SlaEvaluationResult(0, 0, 0, 0, 0)


def evaluate_sla_rules(
    *,
    asset_ids: list[str],
    now: datetime | None = None,
) -> SlaEvaluationResult:
    """Evaluate every enabled SLA rule against findings scoped to asset_ids."""
    if not asset_ids:
        return _empty_sla_result()

    current_time = _ensure_aware(now) if now is not None else _utcnow()

    async def _evaluate(session) -> SlaEvaluationResult:
        rules_q = await session.execute(
            select(Rule).where(
                Rule.category == "sla",
                Rule.enabled == True,  # noqa: E712
            )
        )
        rules = list(rules_q.scalars().all())

        findings_q = await session.execute(
            select(Finding).where(Finding.asset_id.in_(asset_ids))
        )
        findings = list(findings_q.scalars().all())

        active_findings = [f for f in findings if f.state not in _CLOSED_STATES]
        findings_by_id: dict[int, Finding] = {f.id: f for f in findings}

        rule_matches: dict[str, dict[int, datetime]] = {}
        tightest_by_finding: dict[int, tuple[datetime, str]] = {}

        skipped_rules = 0
        for rule in rules:
            action = rule.action or {}
            deadline_days = action.get("deadline_days")
            if not isinstance(deadline_days, int) or deadline_days <= 0:
                logger.warning(
                    "SLA evaluator: rule %s has invalid deadline_days=%r; skipping",
                    rule.id, deadline_days,
                )
                skipped_rules += 1
                continue

            matches: dict[int, datetime] = {}
            for finding in active_findings:
                if not finding.severity:
                    logger.warning(
                        "SLA evaluator: finding %s has no severity; skipping",
                        finding.id,
                    )
                    continue

                first_seen = _ensure_aware(finding.first_seen_at)
                age_days = max(0, (current_time - first_seen).days)
                subject = _finding_to_subject(finding, age_days=age_days)

                try:
                    matched = evaluate_condition(
                        rule.conditions or {}, subject, get_finding_field
                    )
                except Exception:
                    logger.exception(
                        "SLA evaluator: rule %s conditions failed to evaluate for finding %s",
                        rule.id, finding.id,
                    )
                    continue

                if not matched:
                    continue

                deadline_at = first_seen + timedelta(days=deadline_days)
                matches[finding.id] = deadline_at

                existing = tightest_by_finding.get(finding.id)
                if existing is None or deadline_at < existing[0]:
                    tightest_by_finding[finding.id] = (deadline_at, rule.id)

            rule_matches[rule.id] = matches

        rules_evaluated = len(rules) - skipped_rules
        findings_checked = len(active_findings)

        opened = 0
        resolved = 0

        # Open or refresh violations for every (rule, matching finding) pair.
        # ON CONFLICT DO NOTHING guards against the race where a concurrent
        # evaluator inserts the same (rule, subject) open row first; we then
        # re-select and update deadline_at if changed.
        for rule_id, matches in rule_matches.items():
            for finding_id, deadline_at in matches.items():
                new_deadline_iso = deadline_at.isoformat()
                insert_stmt = (
                    pg_insert(RuleViolation)
                    .values(
                        rule_id=rule_id,
                        subject_type="finding",
                        subject_id=str(finding_id),
                        status="open",
                        opened_at=current_time,
                        context={
                            "deadline_at": new_deadline_iso,
                            "escalation_state": {},
                        },
                    )
                    .on_conflict_do_nothing(
                        index_elements=["rule_id", "subject_type", "subject_id"],
                        index_where=sa.text("status = 'open'"),
                    )
                    .returning(RuleViolation.id)
                )
                result = await session.execute(insert_stmt)
                inserted_id = result.scalar_one_or_none()
                if inserted_id is not None:
                    opened += 1
                else:
                    existing_q = await session.execute(
                        select(RuleViolation).where(
                            RuleViolation.rule_id == rule_id,
                            RuleViolation.subject_type == "finding",
                            RuleViolation.subject_id == str(finding_id),
                            RuleViolation.status == "open",
                        )
                    )
                    existing = existing_q.scalar_one_or_none()
                    if existing is not None:
                        ctx = dict(existing.context or {})
                        if ctx.get("deadline_at") != new_deadline_iso:
                            ctx["deadline_at"] = new_deadline_iso
                            if "escalation_state" not in ctx:
                                ctx["escalation_state"] = {}
                            existing.context = ctx

        # Resolve open violations whose finding closed OR no longer matches.
        for rule_id, matches in rule_matches.items():
            open_q = await session.execute(
                select(RuleViolation).where(
                    RuleViolation.rule_id == rule_id,
                    RuleViolation.subject_type == "finding",
                    RuleViolation.status == "open",
                )
            )
            for violation in open_q.scalars().all():
                try:
                    finding_id_int = int(violation.subject_id)
                except (TypeError, ValueError):
                    continue
                finding = findings_by_id.get(finding_id_int)
                if finding is None:
                    continue
                if finding.state in _CLOSED_STATES or finding_id_int not in matches:
                    violation.status = "resolved"
                    violation.resolved_at = current_time
                    resolved += 1

        # Dual-write FindingSlaStatus for EVERY active finding, regardless of
        # whether any rules matched. This mirrors the legacy
        # SlaService.recompute_org behaviour where orgs with no policies still
        # get null-deadline rows written so dashboards don't go stale.
        for finding in active_findings:
            existing_status = await session.get(FindingSlaStatus, finding.id)
            tightest = tightest_by_finding.get(finding.id)
            if tightest is None:
                deadline_at: datetime | None = None
                breached = False
                breach_age_days: int | None = None
            else:
                deadline_at, _rule_id = tightest
                breached = current_time > deadline_at
                breach_age_days = (
                    max(0, (current_time - deadline_at).days) if breached else None
                )

            if existing_status is None:
                session.add(FindingSlaStatus(
                    finding_id=finding.id,
                    deadline_at=deadline_at,
                    breached=breached,
                    breach_age_days=breach_age_days,
                    computed_at=current_time,
                ))
            else:
                existing_status.deadline_at = deadline_at
                existing_status.breached = breached
                existing_status.breach_age_days = breach_age_days
                existing_status.computed_at = current_time

        # Mark rules as evaluated so the UI can show "last run".
        for rule in rules:
            if rule.id in rule_matches:
                rule.last_evaluated_at = current_time

        return SlaEvaluationResult(
            rules_evaluated=rules_evaluated,
            findings_checked=findings_checked,
            violations_opened=opened,
            violations_resolved=resolved,
            escalations_fired=0,
        )

    return run_db(_evaluate)


def evaluate_sla_escalations(*, now: datetime | None = None) -> int:
    """Fire un-fired escalations whose ``at_hours`` threshold has elapsed."""
    current_time = _ensure_aware(now) if now is not None else _utcnow()

    async def _evaluate(session) -> int:
        pairs_q = await session.execute(
            select(RuleViolation, Rule)
            .join(Rule, Rule.id == RuleViolation.rule_id)
            .where(
                Rule.category == "sla",
                Rule.enabled == True,  # noqa: E712
                RuleViolation.status == "open",
                RuleViolation.subject_type == "finding",
            )
        )
        pairs = [(v, r) for v, r in pairs_q.all()]
        if not pairs:
            return 0

        needed_channel_ids: set[int] = set()
        for _violation, rule in pairs:
            for esc in (rule.action or {}).get("escalations") or []:
                cid = esc.get("channel_id")
                if isinstance(cid, int):
                    needed_channel_ids.add(cid)

        destinations_by_channel: dict[int, NotificationDestination | None] = {}
        if needed_channel_ids:
            dest_q = await session.execute(
                select(NotificationDestination).where(
                    NotificationDestination.id.in_(needed_channel_ids),
                )
            )
            for dest in dest_q.scalars().all():
                destinations_by_channel[dest.id] = dest

        total_fired = 0
        for violation, rule in pairs:
            fired = _check_and_fire_escalations(
                violation=violation,
                rule=rule,
                now=current_time,
                destinations_by_channel=destinations_by_channel,
            )
            total_fired += fired
        return total_fired

    return run_db(_evaluate)


def _check_and_fire_escalations(
    *,
    violation: RuleViolation,
    rule: Rule,
    now: datetime,
    destinations_by_channel: dict[int, NotificationDestination | None],
) -> int:
    """Fire any escalation whose ``at_hours`` has elapsed and isn't yet recorded.

    Returns the number of escalations fired this call.
    """
    action = rule.action or {}
    escalations = action.get("escalations") or []
    if not escalations:
        return 0

    context = violation.context or {}
    state = dict(context.get("escalation_state") or {})

    opened_at = _ensure_aware(violation.opened_at)
    elapsed_hours = (now - opened_at).total_seconds() / 3600.0

    fired = 0
    for esc in escalations:
        at_hours = esc.get("at_hours")
        channel_id = esc.get("channel_id")
        if not isinstance(at_hours, int) or not isinstance(channel_id, int):
            logger.warning(
                "SLA evaluator: malformed escalation entry on rule %s: %r",
                rule.id, esc,
            )
            continue

        key = f"{at_hours}h"
        if state.get(key):
            continue
        if elapsed_hours < at_hours:
            continue

        dest = destinations_by_channel.get(channel_id)
        if dest is None or not dest.enabled:
            logger.warning(
                "SLA escalation: destination %s missing or disabled (rule %s, violation %s)",
                channel_id, rule.id, violation.id,
            )
            continue

        _dispatch_escalation(
            rule=rule,
            violation=violation,
            channel_id=channel_id,
            at_hours=at_hours,
        )
        state[key] = now.isoformat()
        fired += 1

    if fired:
        violation.context = {**context, "escalation_state": state}

    return fired


def _dispatch_escalation(
    *,
    rule: Rule,
    violation: RuleViolation,
    channel_id: int,
    at_hours: int,
) -> None:
    """Publish an ``sla.escalation`` event for the notification router to pick up."""
    from src.shared.event_bus import Event, get_event_bus

    get_event_bus().publish_sync(Event(
        event_type="sla.escalation",
        org="",
        data={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "violation_id": violation.id,
            "subject_id": violation.subject_id,
            "at_hours": at_hours,
            "channel_id": channel_id,
            "deadline_at": (violation.context or {}).get("deadline_at"),
        },
    ))
    logger.info(
        "SLA escalation fired: rule=%s violation=%s at_hours=%s channel=%s",
        rule.id, violation.id, at_hours, channel_id,
    )


__all__ = [
    "SlaEvaluationResult",
    "evaluate_sla_rules",
    "evaluate_sla_escalations",
]
