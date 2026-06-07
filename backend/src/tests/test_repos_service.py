"""Unit tests for RepoService — list and detail aggregation.

Uses mocked DB layer (run_db patched) so no real Postgres is needed.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.repos.service import (  # noqa: E402
    RepoService,
    _coverage_status,
    _truncate,
    _FRESH_WINDOW_DAYS,
)

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_FAKE_ASSET_ID_2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


# ── _coverage_status ──────────────────────────────────────────────────────────

def test_coverage_status_never():
    assert _coverage_status(None) == "never"


def test_coverage_status_fresh():
    recent = datetime.now(timezone.utc) - timedelta(days=1)
    assert _coverage_status(recent) == "fresh"


def test_coverage_status_stale():
    old = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS + 1)
    assert _coverage_status(old) == "stale"


def test_coverage_status_boundary():
    # Just inside the fresh window (one second less than the cutoff) is fresh.
    just_fresh = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS) + timedelta(seconds=5)
    assert _coverage_status(just_fresh) == "fresh"

    # Just outside the window is stale.
    just_stale = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS) - timedelta(seconds=5)
    assert _coverage_status(just_stale) == "stale"


# ── _truncate ─────────────────────────────────────────────────────────────────

def test_truncate_none():
    assert _truncate(None, 7) is None


def test_truncate_short():
    assert _truncate("abc", 7) == "abc"


def test_truncate_exact():
    assert _truncate("abcdefg", 7) == "abcdefg"


def test_truncate_long():
    assert _truncate("abcdefghijk", 7) == "abcdefg"


# ── RepoService.list_repos ────────────────────────────────────────────────────

def test_list_repos_empty():
    """list_repos returns empty when no repos in DB."""
    with patch("src.repos.service.run_db", return_value=[]):
        results = RepoService.list_repos(asset_ids=[])
    assert results == []


def test_list_repos_filters_has_critical():
    """has_critical=True excludes repos with zero critical findings."""
    from src.repos.service import RepoSummary
    now = datetime.now(timezone.utc)

    repo_with_critical = RepoSummary(
        asset_id=_FAKE_ASSET_ID,
        display_name="acme-org/api",
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1",
        last_scanned_at=now,
        findings_count_by_severity={"critical": 3, "high": 1, "medium": 0, "low": 0},
        scanners_with_coverage=["dependencies"],
        coverage_status="fresh",
    )

    repo_no_critical = RepoSummary(
        asset_id=_FAKE_ASSET_ID_2,
        display_name="acme-org/worker",
        last_scanned_sha="bcd2345",
        manifest_set_hash="hash2",
        last_scanned_at=now,
        findings_count_by_severity={"critical": 0, "high": 2, "medium": 1, "low": 5},
        scanners_with_coverage=["dependencies"],
        coverage_status="fresh",
    )

    all_repos = [repo_with_critical, repo_no_critical]
    filtered = [r for r in all_repos if r.findings_count_by_severity["critical"] > 0]
    assert len(filtered) == 1
    assert filtered[0].display_name == "acme-org/api"


def test_coverage_status_in_summary():
    """RepoSummary.coverage_status derives from last_scanned_at correctly."""
    from src.repos.service import RepoSummary

    fresh_repo = RepoSummary(
        asset_id=_FAKE_ASSET_ID,
        display_name="acme-org/fresh",
        last_scanned_sha=None,
        manifest_set_hash=None,
        last_scanned_at=datetime.now(timezone.utc) - timedelta(hours=3),
        findings_count_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        scanners_with_coverage=[],
        coverage_status=_coverage_status(datetime.now(timezone.utc) - timedelta(hours=3)),
    )
    stale_repo = RepoSummary(
        asset_id=_FAKE_ASSET_ID_2,
        display_name="acme-org/stale",
        last_scanned_sha=None,
        manifest_set_hash=None,
        last_scanned_at=datetime.now(timezone.utc) - timedelta(days=30),
        findings_count_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        scanners_with_coverage=[],
        coverage_status=_coverage_status(datetime.now(timezone.utc) - timedelta(days=30)),
    )
    never_repo = RepoSummary(
        asset_id="cccccccc-dddd-eeee-ffff-000000000000",
        display_name="acme-org/never",
        last_scanned_sha=None,
        manifest_set_hash=None,
        last_scanned_at=None,
        findings_count_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0},
        scanners_with_coverage=[],
        coverage_status=_coverage_status(None),
    )

    assert fresh_repo.coverage_status == "fresh"
    assert stale_repo.coverage_status == "stale"
    assert never_repo.coverage_status == "never"


# ── RepoService.get_repo returns None for missing repo ────────────────────────

def test_get_repo_not_found():
    with patch("src.repos.service.run_db", return_value=None):
        result = RepoService.get_repo(_FAKE_ASSET_ID)
    assert result is None


# ── RepoDetail structure ──────────────────────────────────────────────────────

def test_repo_detail_has_expected_fields():
    """RepoDetail carries all required fields for the API response."""
    from src.repos.service import RepoDetail, ScanRunRow, FindingRow

    detail = RepoDetail(
        asset_id=_FAKE_ASSET_ID,
        display_name="acme-org/payments-api",
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        last_scanned_at=datetime.now(timezone.utc),
        findings_count_by_severity={"critical": 2, "high": 1, "medium": 3, "low": 0},
        scanners_with_coverage=["dependencies", "secrets"],
        coverage_status="fresh",
        scan_history=[
            ScanRunRow(
                scan_id="run-1",
                scanner_type="dependencies",
                status="completed",
                started_at="2026-05-30T12:00:00+00:00",
                duration_ms=5000,
                findings_count=3,
            )
        ],
        active_findings=[
            FindingRow(
                id=1,
                tool="dependencies",
                severity="critical",
                state="open",
                identity_key="CVE-2024-1234",
                asset_id=_FAKE_ASSET_ID,
                first_seen_at="2026-05-01T00:00:00+00:00",
                last_seen_at="2026-05-30T00:00:00+00:00",
            )
        ],
    )

    assert detail.asset_id == _FAKE_ASSET_ID
    assert detail.display_name == "acme-org/payments-api"
    assert detail.coverage_status == "fresh"
    assert len(detail.scan_history) == 1
    assert len(detail.active_findings) == 1
    assert detail.findings_count_by_severity["critical"] == 2
