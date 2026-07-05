"""DB-backed coverage for the scanner-coverage subject loader.

`load_repo_subject` builds the RuleRepoSubject the scanner-coverage evaluator
consumes. It derives per-tool coverage from the most-recent *completed* ScanRun
per tool, a single deterministic `last_scan_age_days` from the injected clock,
and the human-readable repo_id. These are the exact inputs a coverage rule fires
on, so a regression here silently mis-evaluates coverage.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest
import pytest_asyncio
from sqlalchemy import delete

from src.db.models import Asset, ScanRun
from src.rules.repo_subject_loader import load_repo_subject

_NOW = datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def asset(db_session):
    asset_id = str(uuid.uuid4())
    db_session.add(
        Asset(
            id=asset_id,
            type="repo",
            source="source_connection",
            external_ref=f"github:acme-org/{asset_id}",
            display_name="acme-org/widgets",
            labels=["team-core"],
            tier="production",
        )
    )
    await db_session.commit()
    yield asset_id
    await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


async def _add_run(db_session, asset_id, *, tool, status, finished_at):
    db_session.add(
        ScanRun(
            id=f"run-{uuid.uuid4()}",
            tool=tool,
            asset_id=asset_id,
            status=status,
            finished_at=finished_at,
        )
    )
    await db_session.commit()


@pytest.mark.asyncio
async def test_no_completed_runs_yields_empty_coverage(db_session, asset):
    subj = await load_repo_subject(
        (await db_session.get(Asset, asset)), db_session, now=_NOW
    )
    assert subj.repo_id == "acme-org/widgets"
    assert subj.repo_labels == ["team-core"]
    assert subj.tier == "production"
    assert subj.scanners_with_coverage == []
    assert subj.last_scanned_at is None
    assert subj.last_scan_age_days is None


@pytest.mark.asyncio
async def test_completed_runs_populate_coverage_and_age(db_session, asset):
    await _add_run(
        db_session, asset, tool="dependencies_scanning", status="completed",
        finished_at=_NOW - timedelta(days=3),
    )
    await _add_run(
        db_session, asset, tool="secret_scanning", status="completed",
        finished_at=_NOW - timedelta(days=10),
    )
    subj = await load_repo_subject(
        (await db_session.get(Asset, asset)), db_session, now=_NOW
    )
    assert set(subj.scanners_with_coverage) == {"dependencies_scanning", "secret_scanning"}
    # last_scanned_at is the most-recent finish across tools (3 days ago).
    assert subj.last_scanned_at == _NOW - timedelta(days=3)
    assert subj.last_scan_age_days == 3


@pytest.mark.asyncio
async def test_non_completed_runs_do_not_count_as_coverage(db_session, asset):
    await _add_run(
        db_session, asset, tool="code_scanning", status="running",
        finished_at=None,
    )
    await _add_run(
        db_session, asset, tool="container_scanning", status="failed",
        finished_at=_NOW - timedelta(days=1),
    )
    subj = await load_repo_subject(
        (await db_session.get(Asset, asset)), db_session, now=_NOW
    )
    # Neither a running nor a failed run grants coverage.
    assert subj.scanners_with_coverage == []
    assert subj.last_scanned_at is None


@pytest.mark.asyncio
async def test_most_recent_completed_run_per_tool_wins(db_session, asset):
    await _add_run(
        db_session, asset, tool="dependencies_scanning", status="completed",
        finished_at=_NOW - timedelta(days=20),
    )
    await _add_run(
        db_session, asset, tool="dependencies_scanning", status="completed",
        finished_at=_NOW - timedelta(days=2),
    )
    subj = await load_repo_subject(
        (await db_session.get(Asset, asset)), db_session, now=_NOW
    )
    assert subj.scanners_with_coverage == ["dependencies_scanning"]
    # The newer of the two completed runs drives the age.
    assert subj.last_scan_age_days == 2
