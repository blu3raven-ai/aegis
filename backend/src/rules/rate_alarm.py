"""Rate-alarm guardrail for the auto-dismiss matcher (Guardrail #5).

If a single auto-dismiss rule starts swallowing a runaway share of incoming
findings — usually because the predicate was authored too loosely — we must
stop dismissing, notify the security lead, and disable the rule so a human
can review. The threshold is per-rule; one noisy rule should not be
allowed to mask another rule's real signal.

The window is rolling: we count rule-driven dismissals attributed to this
rule and total newly-opened findings for the org over the last
``rate_alarm_window_minutes`` minutes, then compare the ratio to
``rate_alarm_pct``. Both values are required on the action JSON (validated
by ``AutoDismissAction``) — we fail loudly if either is missing.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding, FindingEvent, Rule
from src.shared.event_bus import Event, get_event_bus


logger = logging.getLogger(__name__)

# Cross-commit contract: the lifecycle hot path (commit 7) MUST write the
# auto-dismiss FindingEvent with these exact values. The rate alarm
# numerator depends on them; if they drift, the alarm silently undercounts
# and never trips. These constants are the single source of truth — import
# them from commit 7's wiring code rather than copying the literals.
AUTO_DISMISS_EVENT_TRIGGERED_BY: str = "scan"
AUTO_DISMISS_EVENT_ACTOR_PREFIX: str = "auto-rule:"


def auto_dismiss_event_actor(rule_id: str) -> str:
    """Build the FindingEvent.actor string for an auto-rule dismissal.
    Used by both the rate alarm numerator and the lifecycle hot path."""
    return f"{AUTO_DISMISS_EVENT_ACTOR_PREFIX}{rule_id}"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def should_rate_alarm_block(session: AsyncSession, rule: Rule) -> bool:
    """Return True if the rule's recent dismissal share exceeds its threshold.

    Compares two counts over the rolling window:
      - dismissals attributed to this specific rule (``actor='auto-rule:<id>'``
        on a FindingEvent with ``to_state='dismissed'`` and
        ``triggered_by='scan'``)
      - newly-opened findings in the same org (``to_state='open'``,
        ``triggered_by='scan'``)

    Returns False if no new findings landed in the window — a zero
    denominator means the rule cannot possibly have crossed the threshold.
    """
    action = rule.action or {}
    pct = action["rate_alarm_pct"]
    window_minutes = action["rate_alarm_window_minutes"]

    window_start = _utcnow() - timedelta(minutes=window_minutes)
    rule_actor = auto_dismiss_event_actor(rule.id)

    dismissed_q = await session.execute(
        select(func.count(FindingEvent.id))
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .where(
            # Rate alarm aggregates across the whole instance — Rule does not
            # yet carry an asset scope; tighten when the Rule model migrates.
            FindingEvent.to_state == "dismissed",
            FindingEvent.triggered_by == AUTO_DISMISS_EVENT_TRIGGERED_BY,
            FindingEvent.actor == rule_actor,
            FindingEvent.created_at >= window_start,
        )
    )
    dismissed_by_rule = dismissed_q.scalar_one() or 0

    total_q = await session.execute(
        select(func.count(FindingEvent.id))
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .where(
            # Rate alarm aggregates across the whole instance — Rule does not
            # yet carry an asset scope; tighten when the Rule model migrates.
            FindingEvent.to_state == "open",
            FindingEvent.triggered_by == AUTO_DISMISS_EVENT_TRIGGERED_BY,
            FindingEvent.created_at >= window_start,
        )
    )
    total_new = total_q.scalar_one() or 0

    if total_new == 0:
        return False

    share_pct = (dismissed_by_rule / total_new) * 100.0
    return share_pct > pct


def dispatch_rate_alarm(rule: Rule, *, org_id: str) -> None:
    """Publish a ``rule.auto_dismiss.rate_alarm`` event for downstream routing.

    Mirrors the dispatch pattern used by the SLA and scanner-coverage
    evaluators: emit the event onto the shared bus and let existing
    notification routing pick it up. Delivery (Slack / email / etc.) is
    out of scope for the rules engine.
    """
    action = rule.action or {}
    get_event_bus().publish_sync(Event(
        event_type="rule.auto_dismiss.rate_alarm",
        org=org_id,
        data={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "rate_alarm_pct": action.get("rate_alarm_pct"),
            "rate_alarm_window_minutes": action.get("rate_alarm_window_minutes"),
        },
    ))
    logger.warning(
        "Auto-dismiss rate alarm tripped: rule=%s org=%s pct=%s window_minutes=%s",
        rule.id, org_id, action.get("rate_alarm_pct"),
        action.get("rate_alarm_window_minutes"),
    )


def auto_disable_rule(session: AsyncSession, rule: Rule, *, reason: str) -> None:
    """Flip ``rule.enabled`` to False so subsequent ingests skip the rule.

    A structured warning carries the reason; we also publish a bus event so
    operators can wire the disable into their on-call surface. We do not
    invoke ``AuditRecorder.record`` from inside the caller's session — that
    helper re-enters ``run_db`` and would deadlock the dedicated DB loop.
    """
    rule.enabled = False
    rule.last_evaluated_at = _utcnow()

    get_event_bus().publish_sync(Event(
        event_type="rule.auto_dismiss.auto_disabled",
        org=rule.org_id,
        data={
            "rule_id": rule.id,
            "rule_name": rule.name,
            "reason": reason,
        },
    ))
    logger.warning(
        "Auto-dismiss rule auto-disabled: rule=%s org=%s reason=%s",
        rule.id, rule.org_id, reason,
    )


__all__ = [
    "AUTO_DISMISS_EVENT_TRIGGERED_BY",
    "AUTO_DISMISS_EVENT_ACTOR_PREFIX",
    "auto_dismiss_event_actor",
    "should_rate_alarm_block",
    "dispatch_rate_alarm",
    "auto_disable_rule",
]
