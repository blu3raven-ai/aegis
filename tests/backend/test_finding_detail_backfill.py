"""Integration tests for the finding_detail_backfill module.

Requires testcontainers Postgres + MinIO (started by conftest.py).

Each test uses an isolated org name to avoid cross-test interference.
Findings are seeded directly via the ORM (bypassing upsert_finding) to
simulate legacy rows whose detail column still contains fat keys with
detail_blob_key = NULL.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_detail_blob import build_blob_key
from src.shared.finding_detail_backfill import BackfillStats, backfill_all
from src.shared.object_store import download_json, list_objects


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOOL = "code_scanning"

# A detail that contains both lean and fat keys for code_scanning.
_FULL_DETAIL = {
    "ruleId": "java/sqli",
    "ruleName": "SQL Injection",
    "filePath": "src/App.java",
    "startLine": 10,
    "endLine": 12,
    "message": "Unsafe query",
    "category": "security",
    "cwe": ["CWE-89"],
    "owasp": [],
    "confidence": "high",
    "language": "java",
    "fileClass": "source",
    "ruleIds": ["java/sqli"],
    # fat keys
    "snippet": "String q = input;",
    "dataflowTrace": {"nodes": [{"file": "App.java", "line": 5}]},
    "fixSuggestion": "Use PreparedStatement",
}

# A detail that contains ONLY lean keys for code_scanning.
_LEAN_ONLY_DETAIL = {
    "ruleId": "java/sqli",
    "startLine": 10,
    "endLine": 12,
    "message": "Unsafe query",
    "category": "security",
    "cwe": ["CWE-89"],
    "owasp": [],
    "confidence": "high",
    "language": "java",
    "fileClass": "source",
    "ruleIds": ["java/sqli"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == org)
        )
    run_db(_del)


def _seed(org: str, identity_key: str, detail: dict) -> Finding:
    """Insert a Finding directly, bypassing upsert_finding, to simulate legacy data."""
    async def _q(session):
        f = Finding(
            tool=_TOOL,
            org=org,
            repo="acme-org/repo",
            identity_key=identity_key,
            state="open",
            severity="high",
            detail=detail,
            # detail_blob_key intentionally left NULL
        )
        session.add(f)
        await session.flush()
        return f
    return run_db(_q)


def _fetch(org: str, identity_key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.org == org,
                Finding.identity_key == identity_key,
            )
        )
        return result.scalars().first()
    return run_db(_q)


def _fetch_all(org: str) -> list[Finding]:
    async def _q(session):
        result = await session.execute(
            select(Finding)
            .where(Finding.tool == _TOOL, Finding.org == org)
            .order_by(Finding.id)
        )
        return list(result.scalars().all())
    return run_db(_q)


def _run_backfill(**kwargs) -> BackfillStats:
    return asyncio.run(backfill_all(**kwargs))


# ---------------------------------------------------------------------------
# Test 1: round-trip happy path (5 fat rows)
# ---------------------------------------------------------------------------

def test_round_trip_fat_rows(s3_endpoint):
    """5 legacy fat rows → blobs written, detail stripped to lean, stats correct."""
    org = "backfill-test-round-trip"
    _clean(org)

    keys = [f"finding-{i}" for i in range(5)]
    for k in keys:
        _seed(org, k, _FULL_DETAIL)

    stats = _run_backfill()

    rows = _fetch_all(org)
    assert len(rows) == 5

    for row in rows:
        expected_key = build_blob_key(row.id)
        assert row.detail_blob_key == expected_key, f"id={row.id} missing blob key"

        # Fat keys must not appear in the lean JSONB column.
        assert "snippet" not in row.detail
        assert "dataflowTrace" not in row.detail
        assert "fixSuggestion" not in row.detail

        # Lean key must still be present.
        assert row.detail.get("ruleId") == "java/sqli"

        # The blob must be downloadable and contain the fat keys.
        blob = download_json(row.detail_blob_key)
        assert blob is not None
        assert blob.get("snippet") == "String q = input;"
        assert "dataflowTrace" in blob

    assert stats.processed >= 5
    assert stats.blobbed >= 5
    assert stats.errored == 0


# ---------------------------------------------------------------------------
# Test 2: lean-only row (Option A — no sentinel, blob_key stays None)
# ---------------------------------------------------------------------------

def test_lean_only_row_blob_key_stays_none(s3_endpoint):
    """A row with only lean keys gets detail_blob_key = NULL after backfill."""
    org = "backfill-test-lean-only"
    _clean(org)

    _seed(org, "lean-finding", _LEAN_ONLY_DETAIL)

    stats = _run_backfill()

    row = _fetch(org, "lean-finding")
    assert row is not None
    # No fat keys → blob_key must remain NULL.
    assert row.detail_blob_key is None

    assert stats.lean_only >= 1
    assert stats.errored == 0


# ---------------------------------------------------------------------------
# Test 3: idempotency — second run processes zero blob-bearing rows
# ---------------------------------------------------------------------------

def test_idempotency_second_run(s3_endpoint):
    """Running backfill twice: blobs written on run-1 are not re-uploaded on run-2."""
    org = "backfill-test-idempotent"
    _clean(org)

    for i in range(3):
        _seed(org, f"idem-{i}", _FULL_DETAIL)

    _run_backfill()

    # Capture blob keys set by first run.
    rows_after_first = _fetch_all(org)
    blob_keys_first = [r.detail_blob_key for r in rows_after_first]
    assert all(k is not None for k in blob_keys_first)

    # Second run: the WHERE clause filters out rows with detail_blob_key IS NOT NULL,
    # so blobbed must be 0 for rows already processed.
    stats2 = _run_backfill()
    assert stats2.blobbed == 0
    assert stats2.errored == 0

    # Row state must be unchanged.
    rows_after_second = _fetch_all(org)
    for r in rows_after_second:
        assert r.detail_blob_key is not None
        assert "snippet" not in r.detail


# ---------------------------------------------------------------------------
# Test 4: mid-batch failure isolation
# ---------------------------------------------------------------------------

def test_mid_batch_failure_isolation(s3_endpoint):
    """put_detail_blob raises on row #3: rows 1,2,4,5 get blobs; row 3 stays NULL."""
    org = "backfill-test-failure"
    _clean(org)

    for i in range(5):
        _seed(org, f"fail-{i}", _FULL_DETAIL)

    rows_before = _fetch_all(org)
    assert len(rows_before) == 5

    # The third row ID to be processed (index 2) will trigger the exception.
    third_id = rows_before[2].id

    original_put = __import__(
        "src.shared.finding_detail_blob",
        fromlist=["put_detail_blob"],
    ).put_detail_blob

    call_count = {"n": 0}

    def _put_with_failure(finding_id, fat):
        call_count["n"] += 1
        if finding_id == third_id:
            raise RuntimeError("injected MinIO failure")
        return original_put(finding_id, fat)

    with patch("src.shared.finding_detail_backfill.put_detail_blob", side_effect=_put_with_failure):
        stats = _run_backfill()

    assert stats.errored == 1
    assert stats.blobbed >= 4   # at least the 4 rows from this org; global scan may add more
    assert stats.processed >= 4  # errored row is not counted as processed

    rows_after = _fetch_all(org)
    for row in rows_after:
        if row.id == third_id:
            assert row.detail_blob_key is None, "failed row must keep NULL blob key"
        else:
            assert row.detail_blob_key == build_blob_key(row.id)

    # Re-run with the real put_detail_blob: only row 3 should be picked up.
    stats2 = _run_backfill()
    assert stats2.blobbed == 1
    assert stats2.errored == 0

    row3 = _fetch(org, "fail-2")
    assert row3 is not None
    assert row3.detail_blob_key == build_blob_key(row3.id)


# ---------------------------------------------------------------------------
# Test 5: dry-run
# ---------------------------------------------------------------------------

def test_dry_run_no_writes(s3_endpoint):
    """Dry-run: all rows stay unmodified, no MinIO objects created, stats reported."""
    org = "backfill-test-dry-run"
    _clean(org)

    for i in range(3):
        _seed(org, f"dry-{i}", _FULL_DETAIL)

    rows_before = _fetch_all(org)
    ids = [r.id for r in rows_before]

    stats = _run_backfill(dry_run=True)

    # No DB writes.
    rows_after = _fetch_all(org)
    for row in rows_after:
        assert row.detail_blob_key is None, "dry-run must not update detail_blob_key"
        assert "snippet" in row.detail, "dry-run must not strip fat keys"

    # No MinIO objects for these findings.
    for fid in ids:
        blob_key = build_blob_key(fid)
        assert download_json(blob_key) is None, f"dry-run must not upload blob for id={fid}"

    assert stats.processed >= 3  # at least the 3 rows from this org; global scan may include more
    assert stats.blobbed == 0
    assert stats.errored == 0


# ---------------------------------------------------------------------------
# Test 6: cursor advance across multiple batches
# ---------------------------------------------------------------------------

def test_cursor_advance_multiple_batches(s3_endpoint):
    """10 rows processed with batch_size=3: all 10 get blobs via correct cursor advance."""
    org = "backfill-test-cursor"
    _clean(org)

    for i in range(10):
        _seed(org, f"cursor-{i}", _FULL_DETAIL)

    stats = asyncio.run(backfill_all(batch_size=3))

    rows = _fetch_all(org)
    assert len(rows) == 10

    for row in rows:
        assert row.detail_blob_key == build_blob_key(row.id), f"id={row.id} not processed"
        assert "snippet" not in row.detail

    assert stats.processed >= 10
    assert stats.blobbed >= 10
    assert stats.errored == 0
