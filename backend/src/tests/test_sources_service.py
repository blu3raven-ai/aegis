"""Unit tests for the sources service — repo aggregation helpers and shape.

Mirrors the previous test_repos_service.py coverage against the consolidated
sources module that replaced repos/service.py.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone, timedelta

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from sqlalchemy import delete  # noqa: E402

from src.db.models import Asset, Finding, ScanRun, Sbom, SbomComponent  # noqa: E402
from src.sources.service import (  # noqa: E402
    RepoDetailView,
    RepoView,
    ScanRunView,
    FindingView,
    _FRESH_WINDOW_DAYS,
    _coverage_status,
    _list_repo_sources_async,
    _repo_coverage_summary,
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


# ── DB-backed coverage regression tests ─────────────────────────────────────
# Coverage is derived from the per-asset Sbom table, NOT from ScanRun rows,
# because org-level "Scan now" runs leave ScanRun.asset_id NULL.


def _repo_asset(display_name: str) -> Asset:
    return Asset(
        id=str(uuid.uuid4()),
        type="repo",
        source="source_connection",
        external_ref=f"github:acme-org/{uuid.uuid4().hex}",
        display_name=display_name,
    )


async def _cleanup(db_session, asset_id: str) -> None:
    await db_session.execute(delete(Finding).where(Finding.asset_id == asset_id))
    await db_session.execute(delete(SbomComponent).where(SbomComponent.asset_id == asset_id))
    await db_session.execute(delete(Sbom).where(Sbom.asset_id == asset_id))
    await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
    await db_session.execute(delete(Asset).where(Asset.id == asset_id))
    await db_session.commit()


@pytest.mark.asyncio
async def test_repo_coverage_summary_counts_full_scope(db_session):
    """Fresh/Stale/Never counted over the whole scope: fresh SBOM, stale SBOM,
    no SBOM, and empty SBOM (→ never) each land in the right bucket."""
    fresh, stale, never, empty = (
        _repo_asset("acme-org/fresh"), _repo_asset("acme-org/stale"),
        _repo_asset("acme-org/never"), _repo_asset("acme-org/empty"),
    )
    for a in (fresh, stale, never, empty):
        db_session.add(a)
    await db_session.flush()
    now = datetime.now(timezone.utc)
    old = now - timedelta(days=_FRESH_WINDOW_DAYS + 5)
    db_session.add_all([
        Sbom(asset_id=fresh.id, commit_sha="HEAD", s3_key=f"{fresh.id}/s", run_id="r1", scanned_at=now),
        SbomComponent(asset_id=fresh.id, purl="pkg:npm/a@1", name="a", version="1", ecosystem="npm"),
        Sbom(asset_id=stale.id, commit_sha="HEAD", s3_key=f"{stale.id}/s", run_id="r2", scanned_at=old),
        SbomComponent(asset_id=stale.id, purl="pkg:npm/b@1", name="b", version="1", ecosystem="npm"),
        # empty: an Sbom row with no components → not covered (never).
        Sbom(asset_id=empty.id, commit_sha="HEAD", s3_key=f"{empty.id}/s", run_id="r3", scanned_at=now),
    ])
    await db_session.commit()
    ids = [fresh.id, stale.id, never.id, empty.id]
    try:
        s = await _repo_coverage_summary(db_session, ids)
        assert s.total == 4
        assert s.fresh == 1
        assert s.stale == 1
        assert s.never == 2  # the never repo + the empty-SBOM repo
    finally:
        for aid in ids:
            await _cleanup(db_session, aid)


@pytest.mark.asyncio
async def test_coverage_from_sbom_despite_org_level_scan_run(db_session):
    """A repo whose only ScanRun is org-level (asset_id NULL) but which has a
    non-empty SBOM must read fresh/covered, not 'never' (the A1 regression)."""
    a = _repo_asset("acme-org/has-sbom")
    db_session.add(a)
    await db_session.flush()
    db_session.add(Sbom(
        asset_id=a.id, commit_sha="HEAD", s3_key=f"{a.id}/sbom.cdx.json",
        run_id="r1", scanned_at=datetime.now(timezone.utc),
    ))
    db_session.add(SbomComponent(
        asset_id=a.id, purl="pkg:npm/left-pad@1.3.0", name="left-pad", version="1.3.0", ecosystem="npm",
    ))
    # Org-level Scan-now envelope: completed but NOT asset-linked.
    db_session.add(ScanRun(id=str(uuid.uuid4()), tool="dependencies_scanning", status="completed",
                           asset_id=None, finished_at=datetime.now(timezone.utc)))
    await db_session.commit()
    try:
        rows = await _list_repo_sources_async(db_session, [a.id], None, None, 50)
        assert len(rows) == 1
        assert rows[0].coverage_status == "fresh"
        assert "dependencies_scanning" in rows[0].scanners_with_coverage
        assert rows[0].last_scanned_at is not None
    finally:
        await _cleanup(db_session, a.id)


@pytest.mark.asyncio
async def test_no_coverage_without_sbom_even_with_other_findings(db_session):
    """A repo with only code/secret findings and no SBOM reads 'never' — the A2
    false-positive fix: non-dependency scans must not count as SBOM coverage."""
    a = _repo_asset("acme-org/code-only")
    db_session.add(a)
    await db_session.flush()
    db_session.add(Finding(tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a.id,
                           state="open", severity="high"))
    await db_session.commit()
    try:
        rows = await _list_repo_sources_async(db_session, [a.id], None, None, 50)
        assert len(rows) == 1
        assert rows[0].coverage_status == "never"
        assert rows[0].scanners_with_coverage == ["code_scanning"]
        assert rows[0].last_scanned_at is None
    finally:
        await _cleanup(db_session, a.id)


@pytest.mark.asyncio
async def test_open_finding_count_includes_non_canonical_severity(db_session):
    """A NULL/non-canonical severity open finding counts toward the card total
    (open_finding_count) even though it has no severity bucket (the A5 fix)."""
    a = _repo_asset("acme-org/null-sev")
    db_session.add(a)
    await db_session.flush()
    db_session.add_all([
        Finding(tool="code_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a.id,
                state="open", severity="high"),
        Finding(tool="secret_scanning", identity_key=f"k-{uuid.uuid4()}", asset_id=a.id,
                state="open", severity=None),
    ])
    await db_session.commit()
    try:
        rows = await _list_repo_sources_async(db_session, [a.id], None, None, 50)
        assert rows[0].open_finding_count == 2
        assert rows[0].finding_counts["high"] == 1
        assert sum(rows[0].finding_counts.values()) == 1  # NULL severity not in the buckets
    finally:
        await _cleanup(db_session, a.id)


@pytest.mark.asyncio
async def test_empty_sbom_is_not_coverage(db_session):
    """An Sbom row with no components (the scan ran but resolved nothing) reads
    'never', matching the detail page's empty state."""
    a = _repo_asset("acme-org/empty-sbom")
    db_session.add(a)
    await db_session.flush()
    db_session.add(Sbom(
        asset_id=a.id, commit_sha="HEAD", s3_key=f"{a.id}/sbom.cdx.json",
        run_id="r1", scanned_at=datetime.now(timezone.utc),
    ))
    await db_session.commit()
    try:
        rows = await _list_repo_sources_async(db_session, [a.id], None, None, 50)
        assert rows[0].coverage_status == "never"
        assert "dependencies_scanning" not in rows[0].scanners_with_coverage
    finally:
        await _cleanup(db_session, a.id)
