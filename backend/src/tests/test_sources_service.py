"""Unit tests for the sources service — repo aggregation helpers and shape.

Mirrors the previous test_repos_service.py coverage against the consolidated
sources module that replaced repos/service.py.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone, timedelta

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.sources.service import (  # noqa: E402
    RepoDetailView,
    RepoView,
    ScanRunView,
    FindingView,
    _FRESH_WINDOW_DAYS,
    _coverage_status,
    _truncate,
)

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_FAKE_ASSET_ID_2 = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


def test_coverage_status_never():
    assert _coverage_status(None) == "never"


def test_coverage_status_fresh():
    recent = datetime.now(timezone.utc) - timedelta(days=1)
    assert _coverage_status(recent) == "fresh"


def test_coverage_status_stale():
    old = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS + 1)
    assert _coverage_status(old) == "stale"


def test_coverage_status_boundary():
    just_fresh = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS) + timedelta(seconds=5)
    assert _coverage_status(just_fresh) == "fresh"
    just_stale = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS) - timedelta(seconds=5)
    assert _coverage_status(just_stale) == "stale"


def test_truncate_none():
    assert _truncate(None, 7) is None


def test_truncate_short():
    assert _truncate("abc", 7) == "abc"


def test_truncate_exact():
    assert _truncate("abcdefg", 7) == "abcdefg"


def test_truncate_long():
    assert _truncate("abcdefghijk", 7) == "abcdefg"


def test_repo_view_carries_expected_fields():
    """RepoView captures the canonical repo summary shape used by the router."""
    now = datetime.now(timezone.utc)
    v = RepoView(
        asset_id=_FAKE_ASSET_ID,
        display_name="acme-org/api",
        last_scanned_at=now,
        finding_counts={"critical": 3, "high": 1, "medium": 0, "low": 0},
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1",
        scanners_with_coverage=["dependencies_scanning"],
        coverage_status="fresh",
    )
    assert v.asset_id == _FAKE_ASSET_ID
    assert v.finding_counts["critical"] == 3
    assert v.coverage_status == "fresh"


def test_repo_detail_view_includes_history_and_findings():
    detail = RepoDetailView(
        asset_id=_FAKE_ASSET_ID,
        display_name="acme-org/payments-api",
        last_scanned_at=datetime.now(timezone.utc),
        finding_counts={"critical": 2, "high": 1, "medium": 3, "low": 0},
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        scanners_with_coverage=["dependencies_scanning", "secret_scanning"],
        coverage_status="fresh",
        scan_history=[
            ScanRunView(
                scan_id="run-1",
                scanner_type="dependencies_scanning",
                status="completed",
                started_at="2026-05-30T12:00:00+00:00",
                duration_ms=5000,
                findings_count=3,
            )
        ],
        active_findings=[
            FindingView(
                id=1,
                tool="dependencies_scanning",
                severity="critical",
                state="open",
                identity_key="CVE-2024-1234",
                asset_id=_FAKE_ASSET_ID,
                first_seen_at="2026-05-01T00:00:00+00:00",
                last_seen_at="2026-05-30T00:00:00+00:00",
            )
        ],
    )
    assert detail.display_name == "acme-org/payments-api"
    assert detail.coverage_status == "fresh"
    assert len(detail.scan_history) == 1
    assert len(detail.active_findings) == 1
    assert detail.finding_counts["critical"] == 2
