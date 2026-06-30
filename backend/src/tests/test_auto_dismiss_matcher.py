"""Coverage for the auto-dismiss matcher entry point and its guards.

`check_auto_dismiss_rules` decides whether an incoming finding is auto-dismissed.
Two guards must never silently regress: an engaged kill switch disables all
auto-dismiss, and an existing decision for the same (tool, asset, identity) is
never re-evaluated. `_snapshot_matched_conditions` freezes the audit record the
caller persists. These are the security-relevant edges; the per-rule predicate
evaluation itself is covered by the rules_engine tests.
"""
from __future__ import annotations

import os
import uuid

os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Decision, Rule, RuleKillSwitch
from src.rules.auto_dismiss_matcher import (
    _snapshot_matched_conditions,
    check_auto_dismiss_rules,
    is_kill_switch_active,
)
from src.rules_engine.subjects import RuleFindingSubject

_TOOL = "dependencies_scanning"


def _subject(**over):
    base = dict(
        finding_id="f-1",
        severity="low",
        scanner=_TOOL,
        repo_id="acme-org/widgets",
        repo_labels=["team-core"],
        repo_archived=False,
        cve_id="CVE-2024-1",
        cwe_id="CWE-79",
        kev_matched=True,
        epss_score=0.4,
        file_path="app/x.py",
        age_days=12,
    )
    base.update(over)
    return RuleFindingSubject(**base)


# ── _snapshot_matched_conditions (pure) ──────────────────────────────────────

def test_snapshot_freezes_conditions_and_all_subject_fields():
    conditions = {"all": [{"field": "severity"}]}
    snap = _snapshot_matched_conditions(conditions, _subject())
    assert snap["conditions"] == conditions
    s = snap["subject_snapshot"]
    assert s == {
        "severity": "low",
        "scanner": _TOOL,
        "repo_id": "acme-org/widgets",
        "repo_labels": ["team-core"],
        "repo_archived": False,
        "cve_id": "CVE-2024-1",
        "cwe_id": "CWE-79",
        "file_path": "app/x.py",
        "age_days": 12,
        "kev_matched": True,
        "epss_score": 0.4,
    }


def test_snapshot_copies_repo_labels_not_aliases():
    labels = ["a", "b"]
    snap = _snapshot_matched_conditions({}, _subject(repo_labels=labels))
    snap["subject_snapshot"]["repo_labels"].append("c")
    # Mutating the snapshot must not reach back into the caller's list.
    assert labels == ["a", "b"]


# ── is_kill_switch_active (DB) ───────────────────────────────────────────────

@pytest_asyncio.fixture
async def clean(db_session):
    await db_session.execute(delete(RuleKillSwitch).where(RuleKillSwitch.category == "auto_dismiss"))
    await db_session.commit()
    created_rules: list[str] = []
    created_decisions: list[str] = []
    yield {"rules": created_rules, "decisions": created_decisions}
    await db_session.execute(delete(RuleKillSwitch).where(RuleKillSwitch.category == "auto_dismiss"))
    if created_rules:
        await db_session.execute(delete(Rule).where(Rule.id.in_(created_rules)))
    if created_decisions:
        await db_session.execute(delete(Decision).where(Decision.id.in_(created_decisions)))
    await db_session.commit()


@pytest.mark.asyncio
async def test_kill_switch_absent_then_present(db_session, clean):
    assert await is_kill_switch_active(db_session, category="auto_dismiss") is False
    db_session.add(RuleKillSwitch(category="auto_dismiss", killed_by="admin"))
    await db_session.commit()
    assert await is_kill_switch_active(db_session, category="auto_dismiss") is True


@pytest.mark.asyncio
async def test_kill_switch_is_category_scoped(db_session, clean):
    db_session.add(RuleKillSwitch(category="data_retention", killed_by="admin"))
    await db_session.commit()
    # A switch on another category does not engage auto_dismiss.
    assert await is_kill_switch_active(db_session, category="auto_dismiss") is False
    await db_session.execute(delete(RuleKillSwitch).where(RuleKillSwitch.category == "data_retention"))
    await db_session.commit()


async def _add_matching_rule(db_session, clean):
    rule_id = f"rule-{uuid.uuid4()}"
    db_session.add(
        Rule(
            id=rule_id,
            category="auto_dismiss",
            name="dismiss everything",
            created_by="tester",
            enabled=True,
            conditions={},  # empty tree matches all subjects
            action={"reason": "duplicate"},
        )
    )
    await db_session.commit()
    clean["rules"].append(rule_id)
    return rule_id


# ── check_auto_dismiss_rules guards (DB) ─────────────────────────────────────

@pytest.mark.asyncio
async def test_kill_switch_short_circuits_before_any_rule(db_session, clean):
    await _add_matching_rule(db_session, clean)
    db_session.add(RuleKillSwitch(category="auto_dismiss", killed_by="admin"))
    await db_session.commit()
    out = await check_auto_dismiss_rules(
        db_session, subject=_subject(), tool=_TOOL, identity_key="ik-1", asset_id=None
    )
    # A matching rule exists, but the engaged switch wins.
    assert out is None


@pytest.mark.asyncio
async def test_existing_decision_short_circuits(db_session, clean):
    await _add_matching_rule(db_session, clean)
    dec = Decision(tool=_TOOL, asset_id=None, identity_key="ik-dup", status="dismissed")
    db_session.add(dec)
    await db_session.commit()
    await db_session.refresh(dec)
    clean["decisions"].append(dec.id)
    out = await check_auto_dismiss_rules(
        db_session, subject=_subject(), tool=_TOOL, identity_key="ik-dup", asset_id=None
    )
    # Already decided → never re-evaluated.
    assert out is None


@pytest.mark.asyncio
async def test_matching_rule_returns_match_with_snapshot(db_session, clean):
    rule_id = await _add_matching_rule(db_session, clean)
    out = await check_auto_dismiss_rules(
        db_session, subject=_subject(), tool=_TOOL, identity_key="ik-new", asset_id=None
    )
    assert out is not None
    assert out.rule_id == rule_id
    assert out.rule_name == "dismiss everything"
    assert out.matched_conditions_snapshot["subject_snapshot"]["severity"] == "low"
    # The matcher wrote the dismissing decision; clean it up.
    await db_session.execute(
        delete(Decision).where(Decision.tool == _TOOL, Decision.identity_key == "ik-new")
    )
    await db_session.commit()
