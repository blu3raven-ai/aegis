"""Integration tests for the SLA rule evaluator.

These tests exercise ``evaluate_sla_rules_for_org`` and
``evaluate_sla_escalations_for_org`` against the test-container Postgres
because the evaluator's behaviour depends on real partial-unique-index upserts
and JSONB roundtrips that are clunky to mock.

Each test seeds only the rows it needs and the autouse cleanup fixture truncates
the relevant tables before/after so tests don't pollute one another.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import (
    Finding,
    FindingSlaStatus,
    NotificationDestination,
    Rule,
    RuleViolation,
)
from src.rules.sla_evaluator import (
    evaluate_sla_escalations_for_org,
    evaluate_sla_rules_for_org,
)


_ORG_A = "org-evaluator-a"
_ORG_B = "org-evaluator-b"


# ── Cleanup fixture ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        # rule_violations FK-cascade-deletes when rules go, but explicitly
        # delete everything so tests don't depend on cascade ordering.
        await session.execute(delete(RuleViolation))
        await session.execute(delete(Rule))
        await session.execute(delete(FindingSlaStatus))
        await session.execute(delete(Finding))
        await session.execute(delete(NotificationDestination))

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_rule(
    *,
    org_id: str = _ORG_A,
    rule_id: str | None = None,
    name: str = "rule-1",
    category: str = "sla",
    enabled: bool = True,
    priority: int = 100,
    conditions: dict | None = None,
    action: dict | None = None,
) -> str:
    rid = rule_id or f"sla-{name}"
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(Rule(
            id=rid,
            org_id=org_id,
            category=category,
            name=name,
            description=None,
            enabled=enabled,
            priority=priority,
            conditions=conditions or {},
            action=action or {"deadline_days": 7, "escalations": []},
            created_by="test-user",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)
    return rid


def _seed_finding(
    *,
    org_id: str = _ORG_A,
    severity: str = "critical",
    state: str = "open",
    first_seen_at: datetime | None = None,
    tool: str = "dependencies",
    identity_key: str | None = None,
) -> int:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        f = Finding(
            tool=tool,
            org=org_id,
            repo="repo-1",
            identity_key=identity_key or f"key-{severity}-{now.timestamp()}",
            state=state,
            severity=severity,
            first_seen_at=first_seen_at or now,
            last_seen_at=now,
            detail={},
            created_at=now,
            updated_at=now,
        )
        session.add(f)
        await session.flush()
        return f.id

    return run_db(_insert)


def _seed_destination(
    *,
    org_id: str = _ORG_A,
    name: str = "test-dest",
    enabled: bool = True,
) -> int:
    async def _insert(session):
        dest = NotificationDestination(
            org_id=org_id,
            destination_type="webhook",
            name=name,
            config={"url": "https://example.test/hook"},
            enabled=enabled,
            event_filter=None,
        )
        session.add(dest)
        await session.flush()
        return dest.id

    return run_db(_insert)


def _open_violations(rule_id: str) -> list[RuleViolation]:
    async def _q(session):
        rows = (
            await session.execute(
                select(RuleViolation).where(
                    RuleViolation.rule_id == rule_id,
                    RuleViolation.status == "open",
                )
            )
        ).scalars().all()
        # detach so tests can read attributes outside the session
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


def _all_violations(rule_id: str) -> list[RuleViolation]:
    async def _q(session):
        rows = (
            await session.execute(
                select(RuleViolation).where(RuleViolation.rule_id == rule_id)
            )
        ).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


def _get_sla_status(finding_id: int) -> FindingSlaStatus | None:
    async def _q(session):
        row = await session.get(FindingSlaStatus, finding_id)
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _update_finding(finding_id: int, **fields):
    async def _u(session):
        f = await session.get(Finding, finding_id)
        for k, v in fields.items():
            setattr(f, k, v)

    run_db(_u)


def _update_violation_context(violation_id: int, *, opened_at=None, context=None):
    async def _u(session):
        v = await session.get(RuleViolation, violation_id)
        if opened_at is not None:
            v.opened_at = opened_at
        if context is not None:
            v.context = context

    run_db(_u)


def _get_rule(rule_id: str) -> Rule:
    async def _q(session):
        r = await session.get(Rule, rule_id)
        if r is not None:
            session.expunge(r)
        return r

    return run_db(_q)


# ── Evaluator: violation lifecycle ───────────────────────────────────────────


def test_evaluator_creates_violation_for_matching_finding():
    rule_id = _seed_rule(
        action={"deadline_days": 7, "escalations": []},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    result = evaluate_sla_rules_for_org(_ORG_A)

    assert result.violations_opened == 1
    assert result.violations_resolved == 0

    violations = _open_violations(rule_id)
    assert len(violations) == 1
    assert violations[0].status == "open"
    assert violations[0].subject_type == "finding"


def test_evaluator_resolves_violation_when_finding_closes():
    rule_id = _seed_rule(
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    finding_id = _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)
    assert len(_open_violations(rule_id)) == 1

    _update_finding(finding_id, state="fixed", fixed_at=datetime.now(timezone.utc))

    result = evaluate_sla_rules_for_org(_ORG_A)
    assert result.violations_resolved == 1
    assert _open_violations(rule_id) == []

    all_v = _all_violations(rule_id)
    assert len(all_v) == 1
    assert all_v[0].status == "resolved"
    assert all_v[0].resolved_at is not None


def test_evaluator_resolves_violation_when_finding_no_longer_matches():
    rule_id = _seed_rule(
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    finding_id = _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)
    assert len(_open_violations(rule_id)) == 1

    # Severity drops below the rule's match condition; finding is still open
    # but the predicate no longer fires — open violation should resolve.
    _update_finding(finding_id, severity="low")

    result = evaluate_sla_rules_for_org(_ORG_A)
    assert result.violations_resolved == 1
    assert _open_violations(rule_id) == []


def test_evaluator_dual_writes_to_finding_sla_status():
    first_seen = datetime.now(timezone.utc) - timedelta(days=2)
    _seed_rule(
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    finding_id = _seed_finding(severity="critical", first_seen_at=first_seen)

    evaluate_sla_rules_for_org(_ORG_A)

    status = _get_sla_status(finding_id)
    assert status is not None
    assert status.deadline_at is not None
    # deadline = first_seen + 7d; we're at first_seen + 2d → not breached
    assert status.breached is False
    expected_deadline = first_seen + timedelta(days=7)
    # tolerate microsecond drift introduced by isoformat → DB roundtrip
    assert abs((status.deadline_at - expected_deadline).total_seconds()) < 1


def test_evaluator_writes_finding_sla_status_with_null_deadline_when_no_rule_matches():
    finding_id = _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)

    status = _get_sla_status(finding_id)
    assert status is not None
    assert status.deadline_at is None
    assert status.breached is False


def test_evaluator_skips_disabled_rule():
    rule_id = _seed_rule(
        enabled=False,
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    result = evaluate_sla_rules_for_org(_ORG_A)

    assert result.violations_opened == 0
    assert _open_violations(rule_id) == []


def test_evaluator_tightest_deadline_wins_for_finding_sla_status():
    first_seen = datetime.now(timezone.utc) - timedelta(days=1)
    _seed_rule(
        rule_id="sla-lenient",
        name="lenient",
        action={"deadline_days": 14},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_rule(
        rule_id="sla-strict",
        name="strict",
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    finding_id = _seed_finding(severity="critical", first_seen_at=first_seen)

    evaluate_sla_rules_for_org(_ORG_A)

    status = _get_sla_status(finding_id)
    assert status is not None
    expected_deadline = first_seen + timedelta(days=7)  # tightest wins
    assert abs((status.deadline_at - expected_deadline).total_seconds()) < 1


def test_evaluator_skips_rule_with_invalid_deadline_days():
    rule_id = _seed_rule(
        action={"deadline_days": 0},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    # Should not crash even though the rule is malformed.
    result = evaluate_sla_rules_for_org(_ORG_A)

    assert result.violations_opened == 0
    assert _open_violations(rule_id) == []


def test_evaluator_idempotent_re_running_creates_no_duplicates():
    rule_id = _seed_rule(
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    r1 = evaluate_sla_rules_for_org(_ORG_A)
    r2 = evaluate_sla_rules_for_org(_ORG_A)

    assert r1.violations_opened == 1
    assert r2.violations_opened == 0  # second run is a no-op
    assert len(_open_violations(rule_id)) == 1


def test_evaluator_does_not_evaluate_other_orgs_findings():
    rule_a = _seed_rule(
        org_id=_ORG_A,
        rule_id="sla-a",
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    # A finding belonging to org B should never produce a violation when
    # evaluating org A.
    _seed_finding(org_id=_ORG_B, severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)

    assert _open_violations(rule_a) == []


def test_evaluator_marks_rule_last_evaluated_at():
    rule_id = _seed_rule(
        action={"deadline_days": 7},
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    assert _get_rule(rule_id).last_evaluated_at is None
    evaluate_sla_rules_for_org(_ORG_A)
    assert _get_rule(rule_id).last_evaluated_at is not None


# ── Escalations ──────────────────────────────────────────────────────────────


def test_escalation_fires_at_threshold():
    dest_id = _seed_destination()
    rule_id = _seed_rule(
        action={
            "deadline_days": 7,
            "escalations": [{"at_hours": 1, "channel_id": dest_id}],
        },
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)
    [violation] = _open_violations(rule_id)

    # Backdate opened_at so 1h threshold has elapsed.
    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    _update_violation_context(
        violation.id, opened_at=two_hours_ago, context={"escalation_state": {}}
    )

    fired = evaluate_sla_escalations_for_org(_ORG_A)
    assert fired == 1

    [v] = _open_violations(rule_id)
    escalation_state = (v.context or {}).get("escalation_state", {})
    assert "1h" in escalation_state

    fired_at_str = escalation_state.get("1h")
    assert isinstance(fired_at_str, str)
    fired_at = datetime.fromisoformat(fired_at_str)
    if fired_at.tzinfo is None:
        fired_at = fired_at.replace(tzinfo=timezone.utc)
    assert abs((datetime.now(timezone.utc) - fired_at).total_seconds()) < 60


def test_escalation_does_not_fire_twice():
    dest_id = _seed_destination()
    rule_id = _seed_rule(
        action={
            "deadline_days": 7,
            "escalations": [{"at_hours": 1, "channel_id": dest_id}],
        },
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)
    [violation] = _open_violations(rule_id)

    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    # Pre-record the 1h escalation as already fired.
    _update_violation_context(
        violation.id,
        opened_at=two_hours_ago,
        context={"escalation_state": {"1h": two_hours_ago.isoformat()}},
    )

    fired = evaluate_sla_escalations_for_org(_ORG_A)
    assert fired == 0


def test_escalation_skips_missing_destination():
    rule_id = _seed_rule(
        action={
            "deadline_days": 7,
            # channel_id=999 — no NotificationDestination row with that ID exists.
            "escalations": [{"at_hours": 1, "channel_id": 999}],
        },
        conditions={"field": "severity", "op": "eq", "value": "critical"},
    )
    _seed_finding(severity="critical")

    evaluate_sla_rules_for_org(_ORG_A)
    [violation] = _open_violations(rule_id)

    two_hours_ago = datetime.now(timezone.utc) - timedelta(hours=2)
    _update_violation_context(
        violation.id, opened_at=two_hours_ago, context={"escalation_state": {}}
    )

    # Should not raise; escalation simply doesn't fire.
    fired = evaluate_sla_escalations_for_org(_ORG_A)
    assert fired == 0

    [v] = _open_violations(rule_id)
    # State unchanged because the destination lookup failed.
    assert (v.context or {}).get("escalation_state") == {}
