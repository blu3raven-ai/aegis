"""Coverage for the data-retention evaluator (archive/delete of scan runs).

This is destructive, irreversible-on-delete logic, so the age gate and the
archive-vs-delete routing are worth pinning. Completes the rule-evaluator family
coverage (auto-dismiss, SLA, scanner-coverage already done).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import Asset, Rule, ScanRun
from src.rules.data_retention_evaluator import evaluate_data_retention
from src.rules.scan_result_subject_loader import build_scan_result_subject

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


# ── build_scan_result_subject (pure) ─────────────────────────────────────────

def test_subject_age_and_repo_from_metadata():
    run = ScanRun(
        id="run-1", tool="dependencies_scanning",
        finished_at=_NOW - timedelta(days=40),
        metadata_json={"repo_id": "acme-org/widgets"},
    )
    subj = build_scan_result_subject(run, now=_NOW)
    assert subj.scan_id == "run-1"
    assert subj.tool == "dependencies_scanning"
    assert subj.repo_id == "acme-org/widgets"
    assert subj.age_days == 40


def test_subject_missing_finished_at_is_age_zero():
    run = ScanRun(id="run-2", tool="code_scanning", finished_at=None)
    subj = build_scan_result_subject(run, now=_NOW)
    assert subj.age_days == 0


def test_subject_missing_repo_metadata_is_empty():
    run = ScanRun(id="run-3", tool="code_scanning", finished_at=_NOW, metadata_json={})
    assert build_scan_result_subject(run, now=_NOW).repo_id == ""


# ── evaluate_data_retention (DB-backed) ──────────────────────────────────────

@pytest_asyncio.fixture
async def make(db_session):
    created = {"assets": [], "rules": [], "runs": []}

    async def _make(*, action_type, after_days, run_age_days):
        asset_id = str(uuid.uuid4())
        rule_id = f"rule-{uuid.uuid4()}"
        run_id = f"run-{uuid.uuid4()}"
        db_session.add(
            Asset(
                id=asset_id, type="repo", source="source_connection",
                external_ref=f"github:acme-org/{asset_id}", display_name="acme-org/widgets",
            )
        )
        db_session.add(
            ScanRun(
                id=run_id, tool="dependencies_scanning", asset_id=asset_id,
                status="completed", finished_at=_NOW - timedelta(days=run_age_days),
                archived=False,
            )
        )
        db_session.add(
            Rule(
                id=rule_id, category="data_retention", name="retain", description="",
                created_by="tester", enabled=True, conditions={},
                action={"type": action_type, "after_days": after_days},
            )
        )
        await db_session.commit()
        created["assets"].append(asset_id)
        created["rules"].append(rule_id)
        created["runs"].append(run_id)
        return {"asset_id": asset_id, "rule_id": rule_id, "run_id": run_id}

    yield _make
    await db_session.execute(delete(ScanRun).where(ScanRun.id.in_(created["runs"])))
    await db_session.execute(delete(Rule).where(Rule.id.in_(created["rules"])))
    await db_session.execute(delete(Asset).where(Asset.id.in_(created["assets"])))
    await db_session.commit()


@pytest.mark.asyncio
async def test_archive_flips_archived_flag(db_session, make):
    seeded = await make(action_type="archive", after_days=30, run_age_days=100)
    result = evaluate_data_retention(asset_ids=[seeded["asset_id"]], now=_NOW)
    assert result.archived == 1
    assert result.deleted == 0
    await db_session.rollback()
    run = await db_session.get(ScanRun, seeded["run_id"])
    assert run is not None and run.archived is True
    assert run.archived_by_rule_id == seeded["rule_id"]


@pytest.mark.asyncio
async def test_delete_removes_the_run(db_session, make):
    seeded = await make(action_type="delete", after_days=90, run_age_days=200)
    result = evaluate_data_retention(asset_ids=[seeded["asset_id"]], now=_NOW)
    assert result.deleted == 1
    await db_session.rollback()
    assert await db_session.get(ScanRun, seeded["run_id"]) is None


@pytest.mark.asyncio
async def test_empty_scope_is_noop(db_session):
    result = evaluate_data_retention(asset_ids=[], now=_NOW)
    assert result.scans_checked == 0
    assert result.archived == 0
    assert result.deleted == 0
