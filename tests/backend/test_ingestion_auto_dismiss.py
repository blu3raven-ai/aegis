"""Integration tests for auto-dismiss via the full ingestion lifecycle path.

Exercises ``apply_lifecycle`` end-to-end against a real testcontainer DB so
the full chain — hooks → identity_key → matcher → Decision row → upsert_finding
(dismissed) → FindingEvent — is covered without any mocking.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, func, select

# Importing compliance models registers the compliance_control_mappings and
# framework_controls tables with Base.metadata before the session-scoped
# _create_tables fixture runs create_all. Without this, upsert_finding (which
# calls apply_finding_mappings) will fail with UndefinedTableError when the
# test file is run in isolation.
import src.compliance.models  # noqa: F401

from src.db.helpers import run_db
from src.db.models import Decision, Finding, FindingEvent, Rule, RuleKillSwitch
from src.rules.rate_alarm import auto_dismiss_event_actor
from src.shared.lifecycle import LifecycleHooks, ScanContext, apply_lifecycle


_ORG = "acme-ingest-org"
_TOOL = "dependencies"


# ── Fake hooks ────────────────────────────────────────────────────────────────


class FakeIngestHooks(LifecycleHooks):
    """Minimal hooks for ingestion integration tests."""

    tool = _TOOL

    def compute_identity_key(self, raw: dict) -> str:
        return f"{raw['repo']}::{raw['key']}"

    def initial_state(self, raw: dict) -> str:
        return "open"

    def extract_repo(self, raw: dict) -> str | None:
        return raw.get("repo")

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity")

    def extract_detail(self, raw: dict) -> dict:
        # Lifecycle's _build_subject_for_new_finding reads cve_id / cwe_id /
        # file_path from the returned dict via detail_dict.get(...)
        return {"source": raw.get("key")}

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True

    def has_fix(self, raw: dict) -> bool:
        return False


# ── Cleanup fixture ───────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_tables():
    """Wipe org-scoped rows before and after each test."""

    async def _del(session):
        await session.execute(
            delete(FindingEvent).where(FindingEvent.org == _ORG)
        )
        await session.execute(
            delete(Decision).where(Decision.org == _ORG)
        )
        await session.execute(
            delete(Finding).where(Finding.org == _ORG)
        )
        await session.execute(
            delete(RuleKillSwitch).where(RuleKillSwitch.org_id == _ORG)
        )
        await session.execute(
            delete(Rule).where(Rule.org_id == _ORG)
        )

    run_db(_del)
    yield
    run_db(_del)


# ── Seeding helpers ───────────────────────────────────────────────────────────


def _seed_rule(
    *,
    rule_id: str = "ingest-rule-1",
    name: str = "ingest test rule",
    enabled: bool = True,
    priority: int = 100,
    conditions: dict | None = None,
) -> str:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(Rule(
            id=rule_id,
            org_id=_ORG,
            category="auto_dismiss",
            name=name,
            description=None,
            enabled=enabled,
            priority=priority,
            conditions=conditions if conditions is not None else {"all": []},
            action={
                "reason": "auto-dismiss for tests",
                "rate_alarm_pct": 99.0,
                "rate_alarm_window_minutes": 60,
            },
            created_by="usr-test",
            created_at=now,
            updated_at=now,
        ))

    run_db(_insert)
    return rule_id


def _seed_kill_switch() -> None:
    now = datetime.now(timezone.utc)

    async def _insert(session):
        session.add(RuleKillSwitch(
            org_id=_ORG,
            category="auto_dismiss",
            killed_at=now,
            killed_by="usr-admin",
            reason="emergency stop",
        ))

    run_db(_insert)


def _make_ctx(run_id: str = "run-ingest-1") -> ScanContext:
    # No checkout_path — confirms auto-dismiss path skips git attribution.
    return ScanContext(tool=_TOOL, org=_ORG, run_id=run_id)


# ── DB query helpers ──────────────────────────────────────────────────────────


def _get_finding(identity_key: str) -> Finding | None:
    async def _q(session):
        row = (await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.org == _ORG,
                Finding.identity_key == identity_key,
            )
        )).scalars().first()
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _get_decision(identity_key: str) -> Decision | None:
    async def _q(session):
        row = (await session.execute(
            select(Decision).where(
                Decision.tool == _TOOL,
                Decision.org == _ORG,
                Decision.identity_key == identity_key,
            )
        )).scalars().first()
        if row is not None:
            session.expunge(row)
        return row

    return run_db(_q)


def _get_events(identity_key: str) -> list[FindingEvent]:
    async def _q(session):
        rows = (await session.execute(
            select(FindingEvent).where(
                FindingEvent.tool == _TOOL,
                FindingEvent.org == _ORG,
                FindingEvent.identity_key == identity_key,
            )
        )).scalars().all()
        for r in rows:
            session.expunge(r)
        return list(rows)

    return run_db(_q)


def _count_events(identity_key: str, *, actor_prefix: str | None = None) -> int:
    async def _q(session):
        stmt = select(func.count(FindingEvent.id)).where(
            FindingEvent.tool == _TOOL,
            FindingEvent.org == _ORG,
            FindingEvent.identity_key == identity_key,
        )
        if actor_prefix is not None:
            stmt = stmt.where(FindingEvent.actor.like(f"{actor_prefix}%"))
        return (await session.execute(stmt)).scalar_one()

    return run_db(_q)


# ── Tests ─────────────────────────────────────────────────────────────────────


def test_ingestion_auto_dismiss_full_path():
    """Happy path: enabled rule with matching condition dismisses the finding."""
    conditions = {"all": [{"field": "severity", "op": "eq", "value": "high"}]}
    rule_id = _seed_rule(rule_id="ingest-rule-happy", conditions=conditions)

    hooks = FakeIngestHooks()
    ctx = _make_ctx(run_id="run-happy-1")
    findings = [{"repo": "acme/api", "key": "k1", "severity": "high"}]

    returned = apply_lifecycle(hooks, ctx, findings)

    # Auto-dismissed finding must NOT appear in the returned new-findings list.
    assert returned == []

    identity_key = "acme/api::k1"
    actor = auto_dismiss_event_actor(rule_id)

    # Finding row: dismissed state.
    f = _get_finding(identity_key)
    assert f is not None
    assert f.state == "dismissed"

    # Decision row: auto-rule actor, correct reason.
    d = _get_decision(identity_key)
    assert d is not None
    assert d.status == "dismissed"
    assert d.reason == "Auto-dismissed by rule"
    assert d.decided_by == actor

    # FindingEvent: one event, actor is auto-rule:<id>, to_state=dismissed,
    # triggered_by=scan, metadata contains conditions and subject_snapshot.
    events = _get_events(identity_key)
    assert len(events) == 1
    ev = events[0]
    assert ev.triggered_by == "scan"
    assert ev.actor == actor
    assert ev.to_state == "dismissed"
    assert ev.from_state is None

    meta = ev.metadata_json
    assert meta is not None
    assert meta["conditions"] == conditions
    snap = meta["subject_snapshot"]
    assert snap["severity"] == "high"


def test_ingestion_kill_switch_blocks_auto_dismiss():
    """Kill switch engaged: finding is ingested as open, no Decision written."""
    _seed_rule(rule_id="ingest-rule-ks", conditions={"all": []})
    _seed_kill_switch()

    hooks = FakeIngestHooks()
    ctx = _make_ctx(run_id="run-ks-1")
    findings = [{"repo": "acme/api", "key": "k2", "severity": "high"}]

    returned = apply_lifecycle(hooks, ctx, findings)

    identity_key = "acme/api::k2"

    # Finding is new and open — appears in returned list.
    assert len(returned) == 1

    f = _get_finding(identity_key)
    assert f is not None
    assert f.state == "open"

    assert _get_decision(identity_key) is None

    # Normal scan event: triggered_by=scan, actor=run_id.
    events = _get_events(identity_key)
    assert len(events) == 1
    ev = events[0]
    assert ev.triggered_by == "scan"
    assert ev.actor == ctx.run_id
    assert ev.to_state == "open"


def test_ingestion_disabled_rule_does_not_dismiss():
    """Disabled rule: scan ingests the finding open, no Decision."""
    _seed_rule(rule_id="ingest-rule-disabled", enabled=False, conditions={"all": []})

    hooks = FakeIngestHooks()
    ctx = _make_ctx(run_id="run-disabled-1")
    findings = [{"repo": "acme/api", "key": "k3", "severity": "high"}]

    returned = apply_lifecycle(hooks, ctx, findings)

    identity_key = "acme/api::k3"

    assert len(returned) == 1

    f = _get_finding(identity_key)
    assert f is not None
    assert f.state == "open"

    assert _get_decision(identity_key) is None


def test_ingestion_idempotent_on_retry():
    """Second identical scan: no duplicate Decision, no extra auto-rule event."""
    conditions = {"all": [{"field": "severity", "op": "eq", "value": "high"}]}
    rule_id = _seed_rule(rule_id="ingest-rule-idem", conditions=conditions)

    hooks = FakeIngestHooks()
    findings = [{"repo": "acme/api", "key": "k4", "severity": "high"}]
    identity_key = "acme/api::k4"
    actor = auto_dismiss_event_actor(rule_id)

    # First scan — auto-dismissed.
    apply_lifecycle(hooks, _make_ctx(run_id="run-idem-1"), findings)

    assert _get_finding(identity_key).state == "dismissed"
    assert _get_decision(identity_key) is not None
    assert _count_events(identity_key, actor_prefix="auto-rule:") == 1

    # Second identical scan — finding already dismissed with Decision, so the
    # lifecycle takes the "decision exists, state=dismissed" branch and only
    # updates last_seen_at. No new auto-rule FindingEvent.
    apply_lifecycle(hooks, _make_ctx(run_id="run-idem-2"), findings)

    assert _get_finding(identity_key).state == "dismissed"
    # Still exactly one Decision row (unique constraint enforces this).
    assert _get_decision(identity_key) is not None
    # Auto-rule event count stays at 1 after second scan.
    assert _count_events(identity_key, actor_prefix="auto-rule:") == 1


def test_ingestion_open_finding_when_no_rule_matches():
    """Rule condition does not match the finding's severity — finding stays open."""
    conditions = {"all": [{"field": "severity", "op": "eq", "value": "critical"}]}
    _seed_rule(rule_id="ingest-rule-nomatch", conditions=conditions)

    hooks = FakeIngestHooks()
    ctx = _make_ctx(run_id="run-nomatch-1")
    findings = [{"repo": "acme/api", "key": "k5", "severity": "low"}]

    returned = apply_lifecycle(hooks, ctx, findings)

    identity_key = "acme/api::k5"

    assert len(returned) == 1

    f = _get_finding(identity_key)
    assert f is not None
    assert f.state == "open"

    assert _get_decision(identity_key) is None


def test_ingestion_no_checkout_path_does_not_crash():
    """Auto-dismiss path skips git attribution; no checkout_path must not crash."""
    _seed_rule(rule_id="ingest-rule-noattr", conditions={"all": []})

    hooks = FakeIngestHooks()
    # ScanContext without checkout_path — confirms _run_attribution returns early.
    ctx = ScanContext(tool=_TOOL, org=_ORG, run_id="run-noattr-1")
    assert ctx.extra.get("checkout_path") is None

    findings = [{"repo": "acme/api", "key": "k6", "severity": "high"}]

    # Must not raise.
    returned = apply_lifecycle(hooks, ctx, findings)

    identity_key = "acme/api::k6"
    assert returned == []
    assert _get_finding(identity_key).state == "dismissed"


def test_ingestion_same_scan_duplicate_identity_key_dismisses_once():
    """Same identity_key appears twice in current_findings — only one Decision
    and one auto-rule FindingEvent must be written."""
    conditions = {"all": [{"field": "severity", "op": "eq", "value": "high"}]}
    rule_id = _seed_rule(rule_id="ingest-rule-dedup", conditions=conditions)

    hooks = FakeIngestHooks()
    ctx = _make_ctx(run_id="run-dedup-1")

    # Duplicate entry with the same repo + key → same identity_key.
    findings = [
        {"repo": "acme/api", "key": "k7", "severity": "high"},
        {"repo": "acme/api", "key": "k7", "severity": "high"},
    ]

    returned = apply_lifecycle(hooks, ctx, findings)

    identity_key = "acme/api::k7"
    actor = auto_dismiss_event_actor(rule_id)

    # No open findings returned.
    assert returned == []

    f = _get_finding(identity_key)
    assert f is not None
    assert f.state == "dismissed"

    # Exactly one Decision row.
    async def _count_decisions(session):
        return (await session.execute(
            select(func.count(Decision.id)).where(
                Decision.tool == _TOOL,
                Decision.org == _ORG,
                Decision.identity_key == identity_key,
            )
        )).scalar_one()

    decision_count = run_db(_count_decisions)
    assert decision_count == 1

    # Exactly one auto-rule FindingEvent.
    assert _count_events(identity_key, actor_prefix="auto-rule:") == 1
