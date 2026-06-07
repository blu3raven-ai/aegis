"""Integration tests for the finding_queryable_backfill module.

Requires testcontainers Postgres (started by conftest.py).

Each test uses an isolated org name to avoid cross-test interference.
Findings are seeded directly via the ORM (bypassing upsert_finding) to
simulate legacy rows whose 5 queryable columns are still NULL.
"""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_queryable_backfill import BackfillStats, backfill_all
from src.shared.finding_queryable_fields import extract_queryable_fields


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_TOOL = "code_scanning"

# Code scanning detail with rule and file.
_CODE_SCANNING_DETAIL = {
    "ruleName": "sql-injection",
    "filePath": "src/db.py",
    "cwe": "CWE-89",
    "message": "Potential SQL injection",
    "language": "python",
    "confidence": "high",
}

# Dependencies detail with cveId, package, and manifest path.
_DEPENDENCIES_DETAIL = {
    "cveId": "CVE-2024-1234",
    "packageName": "requests",
    "manifestPath": "requirements.txt",
    "cvssScore": 7.5,
    "vulnerableVersionRange": "<2.0",
}

# Secrets detail with file path only.
_SECRETS_DETAIL = {
    "detector": "aws_key",
    "filePath": "app/config.py",
    "line": 42,
    "fingerprint": "abc123",
}

# Container scanning detail with cveId and package.
_CONTAINER_DETAIL = {
    "cveId": "CVE-2024-9999",
    "packageName": "openssl",
    "imageName": "alpine",
    "imageTag": "3.18",
}

# Mixed camelCase and snake_case (legacy).
_LEGACY_DETAIL = {
    "cve_id": "CVE-OLD-1",
    "file_path": "old/path.py",
    "title": "Old Title",
    "rule_name": "old_rule",
    "package_name": "old_pkg",
}

# Detail with no queryable keys.
_NO_QUERYABLE_DETAIL = {
    "otherStuff": "nothing-relevant",
    "confidence": "high",
    "line": 42,
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
            # All 5 typed columns intentionally left NULL
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
# Test 1: round-trip happy path (5 rows with different detail shapes)
# ---------------------------------------------------------------------------

def test_round_trip_happy_path():
    """5 legacy rows with different detail shapes → all typed columns populated correctly."""
    org = "backfill-test-round-trip"
    _clean(org)

    details = [
        _CODE_SCANNING_DETAIL,
        _DEPENDENCIES_DETAIL,
        _SECRETS_DETAIL,
        _CONTAINER_DETAIL,
        _LEGACY_DETAIL,
    ]

    for i, detail in enumerate(details):
        _seed(org, f"finding-{i}", detail)

    stats = _run_backfill()

    rows = _fetch_all(org)
    assert len(rows) == 5

    # Verify each row was populated according to its extractor output.
    for i, row in enumerate(rows):
        expected = extract_queryable_fields(details[i])
        assert row.cve_id == expected["cve_id"], f"row {i} cve_id mismatch"
        assert row.file_path == expected["file_path"], f"row {i} file_path mismatch"
        assert row.title == expected["title"], f"row {i} title mismatch"
        assert row.rule_name == expected["rule_name"], f"row {i} rule_name mismatch"
        assert row.package_name == expected["package_name"], f"row {i} package_name mismatch"

    assert stats.processed >= 5
    assert stats.populated >= 5
    assert stats.errored == 0


# ---------------------------------------------------------------------------
# Test 2: lean-only / all-null row (no queryable keys in detail)
# ---------------------------------------------------------------------------

def test_all_null_row_reprocessed():
    """A row with no queryable keys gets all 5 columns NULL and is re-picked on next run."""
    org = "backfill-test-all-null"
    _clean(org)

    _seed(org, "no-queryable", _NO_QUERYABLE_DETAIL)

    stats = _run_backfill()

    row = _fetch(org, "no-queryable")
    assert row is not None
    # All 5 columns must remain NULL.
    assert row.cve_id is None
    assert row.file_path is None
    assert row.title is None
    assert row.rule_name is None
    assert row.package_name is None

    assert stats.processed >= 1
    assert stats.all_null >= 1
    assert stats.errored == 0

    # Run again: the row is re-picked because all 5 columns are still NULL.
    stats2 = _run_backfill()
    assert stats2.processed >= 1
    assert stats2.all_null >= 1
    assert stats2.errored == 0


# ---------------------------------------------------------------------------
# Test 3: idempotency on populated rows
# ---------------------------------------------------------------------------

def test_idempotency_second_run_skips_populated():
    """Running backfill twice: second run skips rows where ANY typed column is populated."""
    org = "backfill-test-idempotent"
    _clean(org)

    # Seed 3 rows with queryable details.
    for i in range(3):
        _seed(org, f"idem-{i}", _CODE_SCANNING_DETAIL)

    # First run.
    stats1 = _run_backfill()

    rows_after_first = _fetch_all(org)
    assert len(rows_after_first) == 3
    assert all(r.rule_name == "sql-injection" for r in rows_after_first)

    # Count rows in this org with all 5 cols NULL before second run.
    null_count_before = sum(
        1 for r in rows_after_first
        if r.cve_id is None and r.file_path is None and r.title is None
        and r.rule_name is None and r.package_name is None
    )
    assert null_count_before == 0, "first run should populate all rows"

    # Second run: WHERE filter excludes rows where ANY of the 5 cols is NOT NULL.
    stats2 = _run_backfill()
    # Rows for this org have at least one col populated, so they should not be re-processed.
    # We only expect rows from this org (and possibly other tests) with all 5 NULL.
    assert stats2.processed == 0 or (
        stats2.processed > 0 and stats2.all_null == stats2.processed
    ), "second run should skip this org's rows (all populated)"


# ---------------------------------------------------------------------------
# Test 4: mid-batch failure isolation
# ---------------------------------------------------------------------------

def test_mid_batch_failure_isolation():
    """Extractor raises on one row: other rows in batch are populated; errored row stays NULL."""
    org = "backfill-test-failure"
    _clean(org)

    for i in range(5):
        _seed(org, f"fail-{i}", _CODE_SCANNING_DETAIL)

    rows_before = _fetch_all(org)
    assert len(rows_before) == 5

    # Rather than patching the global extractor, we'll manually inject a failure
    # by checking detail content. This avoids cross-test pollution from the patch.
    original_extract = __import__(
        "src.shared.finding_queryable_fields",
        fromlist=["extract_queryable_fields"],
    ).extract_queryable_fields

    # Count only calls with _CODE_SCANNING_DETAIL to isolate this test's data.
    call_state = {"count": 0, "failed": False}

    def _extract_with_selective_failure(detail):
        # Only count calls from our test data.
        if detail.get("ruleName") == "sql-injection":
            call_state["count"] += 1
            if call_state["count"] == 3 and not call_state["failed"]:
                call_state["failed"] = True
                raise RuntimeError("injected extractor failure")
        return original_extract(detail)

    with patch("src.shared.finding_queryable_backfill.extract_queryable_fields", side_effect=_extract_with_selective_failure):
        # Run with batch size that will process all 5 rows in one batch.
        stats = _run_backfill(batch_size=10)

    # At least one row errored.
    assert stats.errored >= 1, f"Expected at least 1 error, got {stats.errored}"

    rows_after = _fetch_all(org)
    # Count how many rows are populated vs NULL in this org.
    populated = sum(1 for r in rows_after if r.rule_name is not None)
    null_rows = sum(1 for r in rows_after if r.rule_name is None)

    # At least one row should have failed and stayed NULL.
    assert null_rows >= 1, f"Expected at least 1 null row, got {null_rows}"
    # At least some rows should be populated.
    assert populated >= 1, f"Expected at least 1 populated row, got {populated}"

    # Re-run with the real extractor: all rows should now be populated.
    stats2 = _run_backfill()
    assert stats2.errored == 0, f"Second run had errors: {stats2}"

    # All rows should now be fully populated.
    rows_final = _fetch_all(org)
    for row in rows_final:
        assert row.rule_name == "sql-injection", f"id={row.id} not populated after retry"


# ---------------------------------------------------------------------------
# Test 5: dry-run
# ---------------------------------------------------------------------------

def test_dry_run_no_writes():
    """Dry-run: all rows stay unmodified, stats reported as if work happened."""
    org = "backfill-test-dry-run"
    _clean(org)

    for i in range(3):
        _seed(org, f"dry-{i}", _CODE_SCANNING_DETAIL)

    rows_before = _fetch_all(org)
    ids = [r.id for r in rows_before]

    stats = _run_backfill(dry_run=True)

    # No DB writes.
    rows_after = _fetch_all(org)
    for row in rows_after:
        assert row.rule_name is None, "dry-run must not update rule_name"
        assert row.file_path is None, "dry-run must not update file_path"

    # Stats still counted as if work happened.
    assert stats.processed >= 3
    assert stats.populated >= 3
    assert stats.errored == 0


# ---------------------------------------------------------------------------
# Test 6: cursor advance across multiple batches
# ---------------------------------------------------------------------------

def test_cursor_advance_multiple_batches():
    """10 rows processed with batch_size=3: all 10 get populated via correct cursor."""
    org = "backfill-test-cursor"
    _clean(org)

    for i in range(10):
        _seed(org, f"cursor-{i}", _CODE_SCANNING_DETAIL)

    stats = asyncio.run(backfill_all(batch_size=3))

    rows = _fetch_all(org)
    assert len(rows) == 10

    for row in rows:
        assert row.rule_name == "sql-injection", f"id={row.id} not processed"
        assert row.file_path == "src/db.py", f"id={row.id} not processed"

    assert stats.processed >= 10
    assert stats.populated >= 10
    assert stats.errored == 0
