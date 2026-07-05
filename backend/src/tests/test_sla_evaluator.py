"""Coverage for the SLA evaluator's subject build and breach computation.

`_finding_to_subject` previously read `finding.repo`, which does not exist on
Finding (org/repo live on the asset's external_ref/display_name) — so every SLA
rule evaluation raised AttributeError. This pins the corrected subject build and
the end-to-end breach path, with the repo_id resolved from the asset.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, Finding, FindingSlaStatus, Rule, RuleViolation
from src.rules.sla_evaluator import _finding_to_subject, evaluate_sla_rules

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# ── _finding_to_subject (pure) ───────────────────────────────────────────────

def test_finding_to_subject_uses_resolved_repo_id():
    # A bare in-memory Finding has no `repo` attribute; the subject must take
    # repo_id from the caller-resolved value, not crash reaching for finding.repo.
    f = Finding(
        id=1, severity="High", tool="dependencies_scanning",
        cve_id="CVE-2024-1", file_path="app/x.py",
    )
    subj = _finding_to_subject(f, age_days=7, repo_id="acme-org/widgets")
    assert subj.finding_id == 1
    assert subj.severity == "high"  # normalized lower
    assert subj.scanner == "dependencies_scanning"
    assert subj.repo_id == "acme-org/widgets"
    assert subj.cve_id == "CVE-2024-1"
    assert subj.file_path == "app/x.py"
    assert subj.age_days == 7


def test_finding_to_subject_none_repo_id_becomes_empty_string():
    f = Finding(id=2, severity="low", tool="code_scanning")
    subj = _finding_to_subject(f, age_days=0, repo_id=None)
    assert subj.repo_id == ""


# ── evaluate_sla_rules (DB-backed, end-to-end) ───────────────────────────────

@pytest_asyncio.fixture
async def seeded(db_session):
    asset_id = str(uuid.uuid4())
    rule_id = f"rule-{uuid.uuid4()}"
    db_session.add(
        Asset(
            id=asset_id, type="repo", source="source_connection",
            external_ref=f"github:acme-org/{asset_id}", display_name="acme-org/widgets",
        )
    )
    finding = Finding(
        tool="dependencies_scanning", identity_key=f"k-{asset_id}", asset_id=asset_id,
        severity="high", state="open",
        first_seen_at=_NOW - timedelta(days=10), last_seen_at=_NOW - timedelta(days=10),
    )
    db_session.add(finding)
    db_session.add(
        Rule(
            id=rule_id, category="sla", name="1-day SLA", description="",
            created_by="tester", enabled=True, conditions={}, action={"deadline_days": 1},
        )
    )
    await db_session.commit()
    finding_id = finding.id
    yield {"asset_id": asset_id, "rule_id": rule_id, "finding_id": finding_id}
    # The evaluator writes RuleViolation + FindingSlaStatus on its own connection.
    await db_session.execute(delete(FindingSlaStatus).where(FindingSlaStatus.finding_id == finding_id))
    await db_session.execute(delete(RuleViolation).where(RuleViolation.rule_id == rule_id))
    await db_session.execute(delete(Finding).where(Finding.id == finding_id))
    await db_session.execute(delete(Rule).where(Rule.id == rule_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_evaluate_sla_rules_records_breach_for_overdue_finding(db_session, seeded):
    # Runs the full evaluator (on its own background-loop session) — this would
    # have raised AttributeError on finding.repo before the fix.
    result = evaluate_sla_rules(asset_ids=[seeded["asset_id"]], now=_NOW)
    assert result.findings_checked == 1
    assert result.violations_opened == 1

    # End the current snapshot so the rows the evaluator committed are visible.
    await db_session.rollback()
    status = await db_session.get(FindingSlaStatus, seeded["finding_id"])
    assert status is not None
    # Deadline was first_seen + 1 day = _NOW - 9 days, so it's breached now.
    assert status.breached is True
    assert status.breach_age_days == 9
    assert status.deadline_at == _NOW - timedelta(days=9)


@pytest.mark.asyncio
async def test_evaluate_sla_rules_empty_scope_is_noop(db_session):
    result = evaluate_sla_rules(asset_ids=[], now=_NOW)
    assert result.findings_checked == 0
    assert result.violations_opened == 0
