"""Integration tests for the rate alarm guardrail.

Exercises ``should_rate_alarm_block`` against the test-container Postgres
because the threshold is a SQL ratio over FindingEvent rows that joins to
Finding, and the numerator query depends on actor-string formatting.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import Finding, FindingEvent, Rule
from src.rules.rate_alarm import (
    auto_disable_rule,
    auto_dismiss_event_actor,
    dispatch_rate_alarm,
    should_rate_alarm_block,
)


_ORG = "acme-rate-alarm-org"
_TOOL = "dependencies"
_RULE_ID = "rule-rate-alarm-test"


# ── Cleanup ───────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(delete(FindingEvent).where(FindingEvent.org == _ORG))
        await session.execute(delete(Finding).where(Finding.org == _ORG))
        await session.execute(delete(Rule).where(Rule.org_id == _ORG))

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_rule(
    *,
    rule_id: str = _RULE_ID,
    rate_alarm_pct: float = 50.0,
    rate_alarm_window_minutes: int = 60,
    enabled: bool = True,
) -> Rule:
    """Insert a rule and return a detached SQLA instance for direct evaluator calls."""
    now = datetime.now(timezone.utc)

    async def _insert(session):
        rule = Rule(
            id=rule_id,
            org_id=_ORG,
            category="auto_dismiss",
            name="rate-alarm-test",
            description=None,
            enabled=enabled,
            priority=100,
            conditions={"all": []},
            action={
                "reason": "test",
                "rate_alarm_pct": rate_alarm_pct,
                "rate_alarm_window_minutes": rate_alarm_window_minutes,
            },
            created_by="usr-test",
            created_at=now,
            updated_at=now,
        )
        session.add(rule)
        await session.flush()
        session.expunge(rule)
        return rule

    return run_db(_insert)


def _seed_finding(*, identity_key: str) -> int:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        f = Finding(
            tool=_TOOL,
            org=_ORG,
            repo="repo-1",
            identity_key=identity_key,
            state="open",
            severity="high",
            first_seen_at=now,
            last_seen_at=now,
            detail={},
            created_at=now,
            updated_at=now,
        )
        session.add(f)
        await session.flush()
        return f.id

    return run_db(_insert)


def _seed_event(
    *,
    finding_id: int,
    to_state: str,
    triggered_by: str = "scan",
    actor: str | None = None,
    created_at: datetime | None = None,
    identity_key: str = "key-evt",
) -> None:
    when = created_at or datetime.now(timezone.utc)

    async def _insert(session):
        session.add(FindingEvent(
            finding_id=finding_id,
            tool=_TOOL,
            org=_ORG,
            identity_key=identity_key,
            from_state=None,
            to_state=to_state,
            triggered_by=triggered_by,
            actor=actor,
            metadata_json={},
            created_at=when,
        ))

    run_db(_insert)


def _seed_event_pairs(
    *,
    rule_id: str,
    new_open_count: int,
    auto_dismissed_count: int,
    created_at: datetime | None = None,
) -> None:
    """Seed N open events and M auto-rule-dismissed events for the same rule."""
    actor = auto_dismiss_event_actor(rule_id)
    for i in range(new_open_count):
        fid = _seed_finding(identity_key=f"open-{i}-{(created_at or datetime.now(timezone.utc)).timestamp()}")
        _seed_event(finding_id=fid, to_state="open", triggered_by="scan",
                    actor=None, created_at=created_at, identity_key=f"open-{i}")
    for i in range(auto_dismissed_count):
        fid = _seed_finding(identity_key=f"dism-{i}-{(created_at or datetime.now(timezone.utc)).timestamp()}")
        _seed_event(finding_id=fid, to_state="dismissed", triggered_by="scan",
                    actor=actor, created_at=created_at, identity_key=f"dism-{i}")


def _call_should_rate_alarm_block(rule: Rule) -> bool:
    async def _call(session):
        # Re-attach the rule to a fresh session — should_rate_alarm_block only
        # reads attributes off the dataclass-like Rule, no DB access via the row.
        return await should_rate_alarm_block(session, rule)

    return run_db(_call)


def _get_rule(rule_id: str) -> Rule | None:
    async def _q(session):
        row = (
            await session.execute(select(Rule).where(Rule.id == rule_id))
        ).scalars().first()
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_rate_alarm_does_not_fire_below_threshold():
    rule = _seed_rule(rate_alarm_pct=50.0, rate_alarm_window_minutes=60)
    # 10 newly-opened findings (denominator), 3 auto-dismissed (numerator)
    # 30% < 50% threshold.
    _seed_event_pairs(rule_id=rule.id, new_open_count=10, auto_dismissed_count=3)

    assert _call_should_rate_alarm_block(rule) is False


def test_rate_alarm_fires_when_threshold_crossed():
    rule = _seed_rule(rate_alarm_pct=50.0, rate_alarm_window_minutes=60)
    # 10 opens, 6 dismissals → 60% > 50%.
    _seed_event_pairs(rule_id=rule.id, new_open_count=10, auto_dismissed_count=6)

    assert _call_should_rate_alarm_block(rule) is True


def test_rate_alarm_auto_disables_rule_and_dispatches_notification():
    rule = _seed_rule()

    # auto_disable_rule operates on the attached SQLA instance — call inside
    # a session and verify the persisted row flips to enabled=False.
    async def _do_disable(session):
        attached = (
            await session.execute(select(Rule).where(Rule.id == rule.id))
        ).scalars().first()
        mock_bus = MagicMock()
        with patch("src.rules.rate_alarm.get_event_bus", return_value=mock_bus):
            auto_disable_rule(session, attached, reason="rate_alarm_triggered")
        return mock_bus

    bus = run_db(_do_disable)

    refreshed = _get_rule(rule.id)
    assert refreshed.enabled is False
    assert refreshed.last_evaluated_at is not None
    delta = datetime.now(timezone.utc) - refreshed.last_evaluated_at.replace(tzinfo=timezone.utc) \
        if refreshed.last_evaluated_at.tzinfo is None else \
        datetime.now(timezone.utc) - refreshed.last_evaluated_at
    assert abs(delta.total_seconds()) < 60

    # auto_disable_rule publishes a "rule.auto_dismiss.auto_disabled" event.
    assert bus.publish_sync.call_count == 1
    event = bus.publish_sync.call_args.args[0]
    assert event.event_type == "rule.auto_dismiss.auto_disabled"
    assert event.data["rule_id"] == rule.id
    assert event.data["reason"] == "rate_alarm_triggered"

    # dispatch_rate_alarm publishes "rule.auto_dismiss.rate_alarm" with the
    # threshold + window config.
    mock_bus2 = MagicMock()
    with patch("src.rules.rate_alarm.get_event_bus", return_value=mock_bus2):
        dispatch_rate_alarm(refreshed, org_id=_ORG)

    assert mock_bus2.publish_sync.call_count == 1
    alarm_event = mock_bus2.publish_sync.call_args.args[0]
    assert alarm_event.event_type == "rule.auto_dismiss.rate_alarm"
    assert alarm_event.org == _ORG
    assert alarm_event.data["rule_id"] == rule.id
    assert alarm_event.data["rate_alarm_pct"] == 50.0
    assert alarm_event.data["rate_alarm_window_minutes"] == 60


def test_rate_alarm_window_respects_minutes_config():
    rule = _seed_rule(rate_alarm_pct=50.0, rate_alarm_window_minutes=60)

    # In-window events: 4 opens, 3 dismissals → 75% inside the window alone
    # would trip; we'll add fake outside-window events that should be ignored.
    _seed_event_pairs(rule_id=rule.id, new_open_count=4, auto_dismissed_count=3)

    # Outside-window noise: 100 opens 2h ago — if the window query was wrong
    # and counted these, the ratio would crash and we'd see False.
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    _seed_event_pairs(
        rule_id=rule.id,
        new_open_count=100,
        auto_dismissed_count=0,
        created_at=two_hours_ago,
    )

    # 3/4 = 75% > 50% → True; if the window was ignored, denominator would
    # be 104 (3/104 = 2.9%) and we'd see False. This pins the window.
    assert _call_should_rate_alarm_block(rule) is True


def test_rate_alarm_with_zero_findings_returns_false():
    rule = _seed_rule()

    # No FindingEvents at all → denominator is zero.
    assert _call_should_rate_alarm_block(rule) is False

    # Same result if only outside-window events exist.
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    _seed_event_pairs(
        rule_id=rule.id,
        new_open_count=5,
        auto_dismissed_count=5,
        created_at=two_hours_ago,
    )
    assert _call_should_rate_alarm_block(rule) is False
