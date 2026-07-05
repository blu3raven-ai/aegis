"""Coverage for the auto-dismiss rate-alarm guardrail.

This guardrail trips when an auto-dismiss rule dismisses too large a share of
new findings in a window, and can auto-disable a runaway rule. A bug here
either lets a runaway rule keep silently swallowing findings or wrongly
disables a healthy rule, so the threshold maths and actor/window isolation
matter. The numerator counts dismissals by *this rule's* actor; the
denominator counts all new (open) scan events in the window.
"""
from __future__ import annotations

import os
import types
from datetime import datetime, timedelta, timezone

os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Finding, FindingEvent
from src.rules import rate_alarm
from src.rules.rate_alarm import (
    AUTO_DISMISS_EVENT_ACTOR_PREFIX,
    AUTO_DISMISS_EVENT_TRIGGERED_BY,
    auto_disable_rule,
    auto_dismiss_event_actor,
    dispatch_rate_alarm,
    should_rate_alarm_block,
)

_RULE_ID = "rule-rate-alarm"
_ACTOR = auto_dismiss_event_actor(_RULE_ID)


def _rule(pct=50, window=60):
    return types.SimpleNamespace(
        id=_RULE_ID,
        name="Runaway rule",
        enabled=True,
        last_evaluated_at=None,
        action={"rate_alarm_pct": pct, "rate_alarm_window_minutes": window},
    )


# ── pure helpers ─────────────────────────────────────────────────────────────

def test_actor_helper_and_constants():
    assert AUTO_DISMISS_EVENT_TRIGGERED_BY == "scan"
    assert AUTO_DISMISS_EVENT_ACTOR_PREFIX == "auto-rule:"
    assert auto_dismiss_event_actor("abc") == "auto-rule:abc"


class _FakeBus:
    def __init__(self):
        self.published = []

    def publish_sync(self, event):
        self.published.append(event)


def test_dispatch_rate_alarm_publishes_event(monkeypatch):
    bus = _FakeBus()
    monkeypatch.setattr(rate_alarm, "get_event_bus", lambda: bus)
    dispatch_rate_alarm(_rule(pct=40, window=30))
    assert len(bus.published) == 1
    ev = bus.published[0]
    assert ev.event_type == "rule.auto_dismiss.rate_alarm"
    assert ev.data["rule_id"] == _RULE_ID
    assert ev.data["rate_alarm_pct"] == 40
    assert ev.data["rate_alarm_window_minutes"] == 30


def test_auto_disable_rule_mutates_and_publishes(monkeypatch):
    bus = _FakeBus()
    monkeypatch.setattr(rate_alarm, "get_event_bus", lambda: bus)
    rule = _rule()
    auto_disable_rule(None, rule, reason="rate alarm tripped")
    assert rule.enabled is False
    assert rule.last_evaluated_at is not None
    assert len(bus.published) == 1
    ev = bus.published[0]
    assert ev.event_type == "rule.auto_dismiss.auto_disabled"
    assert ev.data["reason"] == "rate alarm tripped"


# ── should_rate_alarm_block (DB-backed) ──────────────────────────────────────

@pytest_asyncio.fixture
async def finding(db_session):
    # The denominator counts open events across all findings, so wipe the event
    # log first to keep the share deterministic regardless of other modules.
    await db_session.execute(delete(FindingEvent))
    f = Finding(tool="dependencies_scanning", identity_key=f"k-{_RULE_ID}")
    db_session.add(f)
    await db_session.commit()
    await db_session.refresh(f)
    yield f.id
    await db_session.execute(delete(FindingEvent).where(FindingEvent.finding_id == f.id))
    await db_session.execute(delete(Finding).where(Finding.id == f.id))
    await db_session.commit()


async def _event(db, finding_id, *, to_state, actor, triggered_by="scan", minutes_ago=5):
    db.add(
        FindingEvent(
            finding_id=finding_id,
            from_state="open",
            to_state=to_state,
            triggered_by=triggered_by,
            actor=actor,
            created_at=datetime.now(timezone.utc) - timedelta(minutes=minutes_ago),
        )
    )


@pytest.mark.asyncio
async def test_blocks_when_dismissed_share_exceeds_pct(db_session, finding):
    for _ in range(3):
        await _event(db_session, finding, to_state="dismissed", actor=_ACTOR)
    for _ in range(2):
        await _event(db_session, finding, to_state="open", actor="scanner")
    await db_session.commit()
    # 3 dismissed / 2 new = 150% > 50%.
    assert await should_rate_alarm_block(db_session, _rule(pct=50)) is True


@pytest.mark.asyncio
async def test_no_block_when_share_at_or_below_pct(db_session, finding):
    await _event(db_session, finding, to_state="dismissed", actor=_ACTOR)
    for _ in range(10):
        await _event(db_session, finding, to_state="open", actor="scanner")
    await db_session.commit()
    # 1 / 10 = 10% <= 50%.
    assert await should_rate_alarm_block(db_session, _rule(pct=50)) is False


@pytest.mark.asyncio
async def test_zero_new_findings_does_not_block(db_session, finding):
    for _ in range(5):
        await _event(db_session, finding, to_state="dismissed", actor=_ACTOR)
    await db_session.commit()
    # No open events → denominator 0 → never blocks (no div-by-zero).
    assert await should_rate_alarm_block(db_session, _rule(pct=50)) is False


@pytest.mark.asyncio
async def test_dismissals_by_other_actor_are_not_counted(db_session, finding):
    other = auto_dismiss_event_actor("some-other-rule")
    for _ in range(5):
        await _event(db_session, finding, to_state="dismissed", actor=other)
    for _ in range(2):
        await _event(db_session, finding, to_state="open", actor="scanner")
    await db_session.commit()
    # This rule dismissed nothing → 0% → no block.
    assert await should_rate_alarm_block(db_session, _rule(pct=50)) is False


@pytest.mark.asyncio
async def test_dismissals_outside_window_are_not_counted(db_session, finding):
    for _ in range(5):
        await _event(db_session, finding, to_state="dismissed", actor=_ACTOR, minutes_ago=120)
    for _ in range(2):
        await _event(db_session, finding, to_state="open", actor="scanner")
    await db_session.commit()
    # Dismissals are 2h old but the window is 60m → not counted.
    assert await should_rate_alarm_block(db_session, _rule(pct=50, window=60)) is False


@pytest.mark.asyncio
async def test_non_scan_triggered_dismissals_are_not_counted(db_session, finding):
    for _ in range(5):
        await _event(db_session, finding, to_state="dismissed", actor=_ACTOR, triggered_by="manual")
    for _ in range(2):
        await _event(db_session, finding, to_state="open", actor="scanner")
    await db_session.commit()
    # Manual dismissals don't count toward the auto-dismiss rate.
    assert await should_rate_alarm_block(db_session, _rule(pct=50)) is False
