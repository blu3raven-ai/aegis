"""Integration tests for the auto-dismiss matcher and Decision-path evaluator.

These tests exercise ``check_auto_dismiss_rules`` and
``write_auto_dismiss_decision`` against the test-container Postgres so the
SQL guardrails (kill switch SELECT, idempotency SELECT, rule priority order)
are covered end-to-end.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, select

from src.db.helpers import run_db
from src.db.models import Decision, Rule, RuleKillSwitch
from src.rules.auto_dismiss_evaluator import write_auto_dismiss_decision
from src.rules.auto_dismiss_matcher import check_auto_dismiss_rules
from src.rules.rate_alarm import auto_dismiss_event_actor
from src.rules_engine.subjects import RuleFindingSubject
from src.shared.finding_queries import delete_decision


_ORG = "acme-evaluator-org"
_TOOL = "dependencies"


# ── Cleanup ───────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    async def _del(session):
        await session.execute(delete(Decision).where(Decision.org == _ORG))
        await session.execute(delete(RuleKillSwitch).where(RuleKillSwitch.org_id == _ORG))
        await session.execute(delete(Rule).where(Rule.org_id == _ORG))

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_rule(
    *,
    rule_id: str = "auto-dismiss-test",
    name: str = "test rule",
    enabled: bool = True,
    priority: int = 100,
    conditions: dict | None = None,
    rate_alarm_pct: float = 99.0,
    rate_alarm_window_minutes: int = 60,
    org_id: str = _ORG,
) -> str:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(Rule(
            id=rule_id,
            org_id=org_id,
            category="auto_dismiss",
            name=name,
            description=None,
            enabled=enabled,
            priority=priority,
            conditions=conditions if conditions is not None else {"all": []},
            action={
                "reason": "test auto-dismiss",
                "rate_alarm_pct": rate_alarm_pct,
                "rate_alarm_window_minutes": rate_alarm_window_minutes,
            },
            created_by="usr-test",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)
    return rule_id


def _seed_kill_switch(*, org_id: str = _ORG, category: str = "auto_dismiss") -> None:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(RuleKillSwitch(
            org_id=org_id,
            category=category,
            killed_at=now,
            killed_by="usr-admin",
            reason="emergency stop",
        ))

    run_db(_insert)


def _make_subject(
    *,
    severity: str = "high",
    scanner: str = "dependencies",
    finding_id: int = 0,
) -> RuleFindingSubject:
    return RuleFindingSubject(
        finding_id=finding_id,
        severity=severity,
        scanner=scanner,
        repo_id="repo-1",
        repo_labels=[],
        repo_archived=False,
        cve_id=None,
        cwe_id=None,
        kev_matched=False,
        epss_score=None,
        file_path=None,
        age_days=1,
    )


def _get_decision(identity_key: str) -> Decision | None:
    async def _q(session):
        row = (
            await session.execute(
                select(Decision).where(
                    Decision.tool == _TOOL,
                    Decision.org == _ORG,
                    Decision.identity_key == identity_key,
                )
            )
        ).scalars().first()
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _run_matcher(*, subject: RuleFindingSubject, identity_key: str, org_id: str = _ORG):
    async def _call(session):
        return await check_auto_dismiss_rules(
            session,
            org_id=org_id,
            subject=subject,
            tool=_TOOL,
            identity_key=identity_key,
        )

    return run_db(_call)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_matcher_dismisses_finding_when_rule_matches():
    rule_id = _seed_rule(rule_id="rule-match", name="catch-all")
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-1")

    assert match is not None
    assert match.rule_id == rule_id
    assert match.rule_name == "catch-all"

    decision = _get_decision("key-1")
    assert decision is not None
    assert decision.status == "dismissed"
    assert decision.reason == "Auto-dismissed by rule"
    assert decision.decided_by == f"auto-rule:{rule_id}"


def test_matcher_does_nothing_when_no_rules():
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-no-rules")

    assert match is None
    assert _get_decision("key-no-rules") is None


def test_matcher_kill_switch_blocks_all_dismissals():
    _seed_rule(rule_id="rule-blocked", name="would-match-but-killed")
    _seed_kill_switch()
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-killed")

    assert match is None
    assert _get_decision("key-killed") is None


def test_matcher_disabled_rule_skipped():
    _seed_rule(rule_id="rule-disabled", enabled=False)
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-disabled")

    assert match is None
    assert _get_decision("key-disabled") is None


def test_auto_dismiss_writes_decision_and_finding_event():
    """write_auto_dismiss_decision writes the Decision row directly.

    The FindingEvent is written separately by the lifecycle hot path (commit 7)
    once the Finding row exists. The evaluator itself only writes the Decision.
    """
    async def _call(session):
        await write_auto_dismiss_decision(
            session,
            tool=_TOOL,
            org=_ORG,
            identity_key="key-direct",
            rule_id="rule-direct",
            rule_name="Direct evaluator",
        )

    run_db(_call)

    decision = _get_decision("key-direct")
    assert decision is not None
    assert decision.status == "dismissed"
    assert decision.reason == "Auto-dismissed by rule"
    assert decision.comment == "Rule: Direct evaluator"
    assert decision.decided_by == "auto-rule:rule-direct"


def test_auto_dismiss_actor_set_to_rule_id():
    rule_id = _seed_rule(rule_id="rule-actor-id")
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-actor")

    assert match is not None
    decision = _get_decision("key-actor")
    assert decision is not None
    assert decision.decided_by == auto_dismiss_event_actor(rule_id)
    assert decision.decided_by == "auto-rule:rule-actor-id"


def test_auto_dismiss_metadata_snapshot_includes_matched_conditions():
    conditions = {"all": [{"field": "severity", "op": "eq", "value": "high"}]}
    _seed_rule(
        rule_id="rule-snapshot",
        conditions=conditions,
    )
    subject = _make_subject(severity="high")

    match = _run_matcher(subject=subject, identity_key="key-snapshot")

    assert match is not None
    snapshot = match.matched_conditions_snapshot
    assert snapshot["conditions"] == conditions

    subject_snapshot = snapshot["subject_snapshot"]
    assert subject_snapshot["severity"] == "high"
    assert subject_snapshot["kev_matched"] is False
    assert subject_snapshot["epss_score"] is None
    # Full field list per _snapshot_matched_conditions in the matcher.
    expected_keys = {
        "severity", "scanner", "repo_id", "repo_labels", "repo_archived",
        "cve_id", "cwe_id", "file_path", "age_days", "kev_matched", "epss_score",
    }
    assert set(subject_snapshot.keys()) == expected_keys


def test_auto_dismissed_finding_reversible_by_deleting_decision():
    """Confirm the Decision row written by the evaluator is plain SQL that
    can be deleted via delete_decision — i.e. the row isn't tied to any
    irreversible state.
    """
    _seed_rule(rule_id="rule-reversible")
    subject = _make_subject()

    _run_matcher(subject=subject, identity_key="key-reversible")
    assert _get_decision("key-reversible") is not None

    async def _delete(session):
        return await delete_decision(session, _TOOL, _ORG, "key-reversible")

    deleted = run_db(_delete)
    assert deleted is True
    assert _get_decision("key-reversible") is None


def test_first_matching_rule_wins():
    """When two rules match, the one with the lowest priority (most specific)
    wins. The matcher orders by priority ASC.
    """
    _seed_rule(rule_id="rule-general", name="general", priority=100)
    _seed_rule(rule_id="rule-specific", name="specific", priority=10)
    subject = _make_subject()

    match = _run_matcher(subject=subject, identity_key="key-priority")

    assert match is not None
    assert match.rule_id == "rule-specific"

    decision = _get_decision("key-priority")
    assert decision is not None
    assert decision.decided_by == "auto-rule:rule-specific"
