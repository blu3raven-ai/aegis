"""Tests for the CI scan trigger service helpers."""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import Asset, ScanRun


_ORG = "acme-org"
_COMMIT_SHA = "a" * 40
_BRANCH = "main"
_PR_NUMBER = 42


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def asset(db_session):
    """Seed a fresh Asset row for each test; delete it (and its scan_runs) on teardown."""
    asset_id = str(uuid.uuid4())
    row = Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref=f"github:{_ORG}/payments-api-{asset_id[:8]}",
        display_name=f"{_ORG}/payments-api",
        asset_metadata={},
    )
    db_session.add(row)
    await db_session.commit()
    yield row
    await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


def _make_session_patch(db_session):
    """Return a patched get_session that yields the test db_session.

    The service functions call `async with get_session() as session:` then
    commit at the end.  We need to hand them the test session so they read and
    write to the same connection as the seeding code, while skipping the
    commit/rollback wrap (the test teardown handles cleanup).
    """
    @asynccontextmanager
    async def _patched_get_session():
        yield db_session

    return _patched_get_session


async def _seed_scan(db_session, asset_id: str, *, status: str,
                     commit_sha: str = _COMMIT_SHA,
                     pr_number: int | None = None) -> ScanRun:
    """Insert a ScanRun row with the given status."""
    row = ScanRun(
        id=str(uuid.uuid4()),
        tool="dependencies",
        asset_id=asset_id,
        status=status,
        commit_sha=commit_sha,
        pr_number=pr_number,
        feedback_status="not_applicable",
    )
    db_session.add(row)
    await db_session.commit()
    return row


# ── find_inflight_scan ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_find_inflight_returns_existing_queued_scan(db_session, asset):
    from src.scans.service import find_inflight_scan

    seeded = await _seed_scan(db_session, asset.id, status="queued")

    with patch("src.scans.service.get_session", _make_session_patch(db_session)):
        result = await find_inflight_scan(org=_ORG, source_id=asset.id, commit_sha=_COMMIT_SHA)

    assert result is not None
    assert result.id == seeded.id
    assert result.status == "queued"


@pytest.mark.asyncio
async def test_find_inflight_returns_none_for_completed(db_session, asset):
    from src.scans.service import find_inflight_scan

    await _seed_scan(db_session, asset.id, status="completed")

    with patch("src.scans.service.get_session", _make_session_patch(db_session)):
        result = await find_inflight_scan(org=_ORG, source_id=asset.id, commit_sha=_COMMIT_SHA)

    assert result is None


# ── cancel_older_queued_for_pr ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cancel_older_queued_for_pr_marks_older_cancelled(db_session, asset):
    from src.scans.service import cancel_older_queued_for_pr

    kept = await _seed_scan(db_session, asset.id, status="queued", pr_number=_PR_NUMBER)
    old = await _seed_scan(db_session, asset.id, status="queued", pr_number=_PR_NUMBER)

    with patch("src.scans.service.get_session", _make_session_patch(db_session)):
        cancelled_ids = await cancel_older_queued_for_pr(
            org=_ORG,
            source_id=asset.id,
            pr_number=_PR_NUMBER,
            keep_scan_id=kept.id,
        )

    assert old.id in cancelled_ids
    assert kept.id not in cancelled_ids

    await db_session.refresh(old)
    await db_session.refresh(kept)

    assert old.status == "cancelled"
    assert old.cancelled_reason == "superseded"
    assert kept.status == "queued"


# ── submit_ci_scan ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_submit_ci_scan_creates_run_with_metadata(db_session, asset):
    from src.scans.service import ScanSubmission, submit_ci_scan

    meta = {"ci_provider": "github_actions", "workflow": "ci.yml"}

    with patch("src.scans.service.get_session", _make_session_patch(db_session)), \
         patch("src.scans.service._dispatch_scanner_jobs") as mock_dispatch:
        submission = await submit_ci_scan(
            org=_ORG,
            source_id=asset.id,
            commit_sha=_COMMIT_SHA,
            branch=_BRANCH,
            pr_number=_PR_NUMBER,
            api_key_id=7,
            trigger_metadata=meta,
        )

    assert isinstance(submission, ScanSubmission)
    assert submission.commit_sha == _COMMIT_SHA
    assert submission.repo_id == asset.id
    assert submission.status == "queued"
    assert submission.submitted_by == "api_key:7"

    mock_dispatch.assert_called_once()

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == submission.scan_id)
    )).scalar_one()

    assert row.triggered_by == "ci"
    assert row.commit_sha == _COMMIT_SHA
    assert row.branch == _BRANCH
    assert row.pr_number == _PR_NUMBER
    assert row.feedback_status == "pending"
    assert row.trigger_metadata == meta
    assert row.status == "queued"


@pytest.mark.asyncio
async def test_submit_ci_scan_no_pr_sets_not_applicable(db_session, asset):
    from src.scans.service import submit_ci_scan

    with patch("src.scans.service.get_session", _make_session_patch(db_session)), \
         patch("src.scans.service._dispatch_scanner_jobs"):
        submission = await submit_ci_scan(
            org=_ORG,
            source_id=asset.id,
            commit_sha=_COMMIT_SHA,
            branch=_BRANCH,
            pr_number=None,
            api_key_id=3,
            trigger_metadata=None,
        )

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == submission.scan_id)
    )).scalar_one()

    assert row.feedback_status == "not_applicable"
    assert row.pr_number is None
    # When caller passes trigger_metadata=None, defaults to {"api_key_id": api_key_id}
    assert row.trigger_metadata == {"api_key_id": 3}


# ── webhook caller shape (api_key_id=None, triggered_by="webhook") ──────────

@pytest.mark.asyncio
async def test_submit_ci_scan_webhook_shape(db_session, asset):
    from src.scans.service import submit_ci_scan

    meta = {"provider": "github", "event_id": "evt-1"}

    with patch("src.scans.service.get_session", _make_session_patch(db_session)), \
         patch("src.scans.service._dispatch_scanner_jobs"):
        submission = await submit_ci_scan(
            org="",
            source_id=asset.id,
            commit_sha=_COMMIT_SHA,
            branch="main",
            pr_number=None,
            triggered_by="webhook",
            trigger_metadata=meta,
        )

    # Webhook-shaped principal carries the event_id from trigger_metadata.
    assert submission.submitted_by == "webhook:evt-1"

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == submission.scan_id)
    )).scalar_one()
    assert row.triggered_by == "webhook"
    assert row.trigger_metadata == meta


@pytest.mark.asyncio
async def test_submit_ci_scan_webhook_default_metadata_is_empty_dict(db_session, asset):
    """With api_key_id=None and trigger_metadata=None, metadata must NOT
    contain a stray ``{"api_key_id": None}`` entry."""
    from src.scans.service import submit_ci_scan

    with patch("src.scans.service.get_session", _make_session_patch(db_session)), \
         patch("src.scans.service._dispatch_scanner_jobs"):
        submission = await submit_ci_scan(
            org="",
            source_id=asset.id,
            commit_sha=_COMMIT_SHA,
            branch="main",
            pr_number=None,
            triggered_by="webhook",
        )

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == submission.scan_id)
    )).scalar_one()
    assert row.trigger_metadata == {}
