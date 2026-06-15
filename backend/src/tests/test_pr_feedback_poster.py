"""Tests for the PR feedback poster loop."""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from src.db.models import Asset, ScanRun
from src.pr_feedback.git_pr_providers.base import AuthError


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_session_patch(db_session):
    """Return a patched get_session that yields the test db_session."""
    @asynccontextmanager
    async def _patched_get_session():
        yield db_session

    return _patched_get_session


class _FakeProvider:
    def __init__(self):
        self.posted = []

    def post_or_update_comment(self, *, repo, pr_number, body, marker, token):
        self.posted.append({"repo": repo, "pr_number": pr_number, "body": body, "marker": marker})


class _FakeSource:
    def __init__(self, id, stored_pat, base_sha="base000"):
        self.id = id
        self.scm_type = "github"
        self.stored_pat = stored_pat
        self._base = base_sha

    def base_sha_for_pr(self, pr_number):
        return self._base


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def seeded_pending_pr_scan(db_session):
    asset_id = str(uuid.uuid4())
    asset = Asset(
        id=asset_id,
        type="repo",
        source="source_connection",
        external_ref=f"github.com/acme-org/api-{asset_id[:8]}",
        display_name="acme-org/api",
    )
    db_session.add(asset)
    await db_session.commit()

    scan = ScanRun(
        id="scan-pending-1",
        tool="dependencies",
        asset_id=asset_id,
        status="completed",
        triggered_by="ci",
        commit_sha="head111",
        pr_number=247,
        feedback_status="pending",
    )
    db_session.add(scan)
    await db_session.commit()
    yield scan
    await db_session.execute(delete(ScanRun).where(ScanRun.id == "scan-pending-1"))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_processes_pending_pr_scan_and_marks_posted(db_session, seeded_pending_pr_scan):
    """A pending PR scan with a valid PAT should be posted and marked 'posted'."""
    import src.pr_feedback.poster as poster_mod

    scan = seeded_pending_pr_scan
    source = _FakeSource(id=scan.asset_id, stored_pat="ghp_fake", base_sha="base000")
    provider = _FakeProvider()

    with patch("src.pr_feedback.poster.get_session", _make_session_patch(db_session)), \
         patch.object(poster_mod, "_list_findings_for_scan", return_value=[
             {"fingerprint": "fp1", "severity": "high", "title": "CVE-2024-1234"},
         ]), \
         patch.object(poster_mod, "_list_findings_for_base", return_value=[]), \
         patch.object(poster_mod, "_resolve_source", return_value=source):

        result = await poster_mod.process_pending_once(
            provider=provider,
            aegis_url="https://aegis.example.com",
        )

    assert result["processed"] == 1
    assert result["posted"] == 1
    assert result["failed"] == 0
    assert result["skipped"] == 0

    # Provider should have received exactly one call
    assert len(provider.posted) == 1
    assert provider.posted[0]["pr_number"] == 247
    assert "1 new findings" in provider.posted[0]["body"]

    # Row should be updated in DB
    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == scan.id)
    )).scalar_one()
    assert row.feedback_status == "posted"


@pytest.mark.asyncio
async def test_no_pending_returns_zero(db_session):
    """When there are no pending PR scans, counters should all be zero."""
    import src.pr_feedback.poster as poster_mod

    provider = _FakeProvider()

    with patch("src.pr_feedback.poster.get_session", _make_session_patch(db_session)):
        result = await poster_mod.process_pending_once(
            provider=provider,
            aegis_url="https://aegis.example.com",
        )

    assert result["processed"] == 0
    assert result["posted"] == 0
    assert result["failed"] == 0
    assert result["skipped"] == 0


@pytest.mark.asyncio
async def test_missing_pat_skips_and_marks_skipped(db_session, seeded_pending_pr_scan):
    """A scan whose source has no PAT should be skipped, not failed."""
    import src.pr_feedback.poster as poster_mod

    scan = seeded_pending_pr_scan
    source = _FakeSource(id=scan.asset_id, stored_pat=None)
    provider = _FakeProvider()

    with patch("src.pr_feedback.poster.get_session", _make_session_patch(db_session)), \
         patch.object(poster_mod, "_resolve_source", return_value=source):

        result = await poster_mod.process_pending_once(
            provider=provider,
            aegis_url="https://aegis.example.com",
        )

    assert result["skipped"] == 1
    assert result["posted"] == 0
    assert len(provider.posted) == 0

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == scan.id)
    )).scalar_one()
    assert row.feedback_status == "skipped"


@pytest.mark.asyncio
async def test_auth_error_marks_failed(db_session, seeded_pending_pr_scan):
    """An AuthError from the provider should mark the scan as 'failed'."""
    import src.pr_feedback.poster as poster_mod

    scan = seeded_pending_pr_scan
    source = _FakeSource(id=scan.asset_id, stored_pat="ghp_expired")
    provider = _FakeProvider()

    def _raise_auth(*args, **kwargs):
        raise AuthError("token revoked")

    provider.post_or_update_comment = _raise_auth

    with patch("src.pr_feedback.poster.get_session", _make_session_patch(db_session)), \
         patch.object(poster_mod, "_list_findings_for_scan", return_value=[]), \
         patch.object(poster_mod, "_list_findings_for_base", return_value=[]), \
         patch.object(poster_mod, "_resolve_source", return_value=source):

        result = await poster_mod.process_pending_once(
            provider=provider,
            aegis_url="https://aegis.example.com",
        )

    assert result["failed"] == 1
    assert result["posted"] == 0

    row = (await db_session.execute(
        select(ScanRun).where(ScanRun.id == scan.id)
    )).scalar_one()
    assert row.feedback_status == "failed"
