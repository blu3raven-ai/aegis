"""Coverage for the scanner-coverage evaluator's violation path.

The evaluator opens a RuleViolation when a repo is missing a required scanner.
rule_violations.asset_id is NOT NULL, but the insert previously omitted it — so
opening a violation raised NotNullViolation. This pins the require_scanners path
end-to-end (asset with no completed scans → violation opened with asset_id set).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone

os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import Asset, Rule, RuleViolation
from src.rules.scanner_coverage_evaluator import evaluate_scanner_coverage

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def seeded(db_session):
    asset_id = str(uuid.uuid4())
    rule_id = f"rule-{uuid.uuid4()}"
    db_session.add(
        Asset(
            id=asset_id, type="repo", source="source_connection",
            external_ref=f"github:acme-org/{asset_id}", display_name="acme-org/widgets",
            archived=False,
        )
    )
    db_session.add(
        Rule(
            id=rule_id, category="scanner_coverage", name="require deps", description="",
            created_by="tester", enabled=True, conditions={},
            action={"type": "require_scanners", "required_scanners": ["dependencies_scanning"]},
        )
    )
    await db_session.commit()
    yield {"asset_id": asset_id, "rule_id": rule_id}
    await db_session.execute(delete(RuleViolation).where(RuleViolation.rule_id == rule_id))
    await db_session.execute(delete(Rule).where(Rule.id == rule_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_missing_scanner_opens_violation_with_asset_id(db_session, seeded):
    # The asset has no completed scans, so the required scanner is missing and a
    # violation must open — this would have raised NotNullViolation before the fix.
    result = evaluate_scanner_coverage(asset_ids=[seeded["asset_id"]], now=_NOW)
    assert result.violations_opened == 1

    await db_session.rollback()  # see the row the evaluator committed
    rows = (
        await db_session.execute(
            select(RuleViolation).where(RuleViolation.rule_id == seeded["rule_id"])
        )
    ).scalars().all()
    assert len(rows) == 1
    v = rows[0]
    assert v.asset_id == seeded["asset_id"]
    assert v.subject_type == "repo"
    assert v.subject_id == "acme-org/widgets"
    assert v.status == "open"
    assert v.context["missing_scanners"] == ["dependencies_scanning"]


@pytest.mark.asyncio
async def test_empty_scope_is_noop(db_session):
    result = evaluate_scanner_coverage(asset_ids=[], now=_NOW)
    assert result.repos_checked == 0
    assert result.violations_opened == 0
