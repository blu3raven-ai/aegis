"""Auto-dismiss rule matcher (Guardrails #4 + #5 entry point).

Called from inside the ingestion lifecycle's existing async session per
incoming finding subject. Returns the metadata of the first matching rule
so the caller can stamp a FindingEvent with the matched-conditions
snapshot once the Finding row exists.

Guardrails enforced inside this module:
  #4 — kill switch: a single SELECT on ``rule_kill_switches`` short-circuits
       every auto-dismiss decision for the org when active.
  #5 — rate alarm: before dismissing, check the rule's share of recent
       ingestions; if exceeded, dispatch a rate alarm, auto-disable the
       rule, and refuse to dismiss this finding.

Determinism: rules are ordered by ``priority`` ASC then ``id`` ASC.
Idempotency: if a Decision already exists for ``(tool, org, identity_key)``
the matcher returns None so the existing decision wins.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Decision, Rule, RuleKillSwitch
from src.rules.auto_dismiss_evaluator import write_auto_dismiss_decision
from src.rules.rate_alarm import (
    auto_disable_rule,
    dispatch_rate_alarm,
    should_rate_alarm_block,
)
from src.rules_engine.conditions import evaluate_condition
from src.rules_engine.subjects import RuleFindingSubject, get_finding_field


logger = logging.getLogger(__name__)


@dataclass
class AutoDismissMatch:
    """Metadata for the rule that auto-dismissed an incoming finding."""
    rule_id: str
    rule_name: str
    matched_conditions_snapshot: dict


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def is_kill_switch_active(
    session: AsyncSession, *, org_id: str, category: str
) -> bool:
    """Row presence in ``rule_kill_switches`` means the switch is engaged."""
    result = await session.execute(
        select(RuleKillSwitch.id).where(
            RuleKillSwitch.org_id == org_id,
            RuleKillSwitch.category == category,
        ).limit(1)
    )
    return result.scalar_one_or_none() is not None


def _snapshot_matched_conditions(
    conditions: dict, subject: RuleFindingSubject
) -> dict[str, Any]:
    """Freeze the rule's predicate tree + subject field values at decision time.

    The snapshot is persisted to ``FindingEvent.metadata_json`` by the
    caller so audit history survives later rule edits or deletes.
    """
    return {
        "conditions": conditions,
        "subject_snapshot": {
            "severity": subject.severity,
            "scanner": subject.scanner,
            "repo_id": subject.repo_id,
            "repo_labels": list(subject.repo_labels),
            "repo_archived": subject.repo_archived,
            "cve_id": subject.cve_id,
            "cwe_id": subject.cwe_id,
            "file_path": subject.file_path,
            "age_days": subject.age_days,
            "kev_matched": subject.kev_matched,
            "epss_score": subject.epss_score,
        },
    }


async def check_auto_dismiss_rules(
    session: AsyncSession,
    *,
    org_id: str,
    subject: RuleFindingSubject,
    tool: str,
    identity_key: str,
    asset_id: str | None = None,
) -> AutoDismissMatch | None:
    """Evaluate enabled auto-dismiss rules against an incoming finding subject.

    On match: writes the Decision row (side effect) and returns metadata so
    the caller can write the corresponding FindingEvent once the Finding
    row exists. Returns None when no rule matches, the kill switch is
    active, the rate alarm trips, or a Decision already exists.
    """
    if await is_kill_switch_active(session, org_id=org_id, category="auto_dismiss"):
        return None

    if asset_id is not None:
        existing_q = await session.execute(
            select(Decision.id).where(
                Decision.tool == tool,
                Decision.asset_id == asset_id,
                Decision.identity_key == identity_key,
            ).limit(1)
        )
    else:
        existing_q = await session.execute(
            select(Decision.id).where(
                Decision.tool == tool,
                Decision.asset_id.is_(None),
                Decision.identity_key == identity_key,
            ).limit(1)
        )
    if existing_q.scalar_one_or_none() is not None:
        return None

    rules_q = await session.execute(
        select(Rule).where(
            Rule.category == "auto_dismiss",
            Rule.enabled == True,  # noqa: E712
            Rule.org_id == org_id,
        ).order_by(Rule.priority.asc(), Rule.id.asc())
    )
    rules = list(rules_q.scalars().all())

    for rule in rules:
        try:
            matched = evaluate_condition(
                rule.conditions or {}, subject, get_finding_field
            )
        except Exception:
            logger.exception(
                "Auto-dismiss matcher: rule %s conditions failed for finding %s/%s",
                rule.id, tool, identity_key,
            )
            continue

        if not matched:
            continue

        if await should_rate_alarm_block(session, rule):
            dispatch_rate_alarm(rule, org_id=org_id)
            auto_disable_rule(session, rule, reason="rate_alarm_triggered")
            return None

        await write_auto_dismiss_decision(
            session,
            tool=tool,
            org=org_id,
            asset_id=asset_id,
            identity_key=identity_key,
            rule_id=rule.id,
            rule_name=rule.name,
        )
        rule.last_evaluated_at = _utcnow()
        snapshot = _snapshot_matched_conditions(rule.conditions or {}, subject)
        return AutoDismissMatch(
            rule_id=rule.id,
            rule_name=rule.name,
            matched_conditions_snapshot=snapshot,
        )

    return None


__all__ = [
    "AutoDismissMatch",
    "check_auto_dismiss_rules",
    "is_kill_switch_active",
]
