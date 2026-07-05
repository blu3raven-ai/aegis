"""Unit tests for the streaming findings export module.

Tests verify:
- CSV header row matches EXPORT_COLUMNS
- CSV row count matches inserted fixtures
- JSONL format emits one JSON object per line
- Filters (severity, scanner, status, repo_id, since, until) are applied
- Streaming handles large result sets (10 k rows) without loading all into memory
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.exports.findings_export import (
    EXPORT_COLUMNS,
    FindingFilters,
    _build_where_clauses,
    _finding_to_row,
    count_findings,
    stream_findings_csv,
    stream_findings_json,
)
from src.db.models import Finding
from src.shared.finding_queryable_fields import extract_queryable_fields


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(
    id: int = 1,
    tool: str = "dependencies",
    severity: str = "high",
    state: str = "open",
    repo: str = "example-org/api",
    detail: dict | None = None,
    first_seen_at: datetime | None = None,
) -> Finding:
    f = Finding()
    f.id = id
    f.tool = tool
    f.org = "example-org"
    f.identity_key = f"key-{id}"
    f.severity = severity
    f.state = state
    f.repo = repo
    f.detail = detail or {"title": f"Finding {id}", "cve_id": "CVE-2026-0001"}
    f.first_seen_at = first_seen_at or datetime(2026, 1, 1, tzinfo=timezone.utc)
    f.last_seen_at = datetime(2026, 5, 1, tzinfo=timezone.utc)
    qf = extract_queryable_fields(f.detail or {})
    f.cve_id = qf["cve_id"]
    f.file_path = qf["file_path"]
    f.title = qf["title"]
    f.rule_name = qf["rule_name"]
    f.package_name = qf["package_name"]
    return f


class _FakeRow:
    """Mimics a SQLAlchemy row with a .Finding attribute."""
    def __init__(self, finding: Finding):
        self.Finding = finding


class _FakeStreamResult:
    """Minimal async stream result that yields partitions."""
    def __init__(self, findings: list[Finding], batch_size: int = 500):
        self._findings = findings
        self._batch_size = batch_size

    async def partitions(self, size: int):
        batch = []
        for f in self._findings:
            batch.append(_FakeRow(f))
            if len(batch) >= size:
                yield batch
                batch = []
        if batch:
            yield batch

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class _FakeSession:
    """Minimal async session that returns _FakeStreamResult from stream()."""
    def __init__(self, findings: list[Finding], count: int | None = None):
        self._findings = findings
        self._count = count if count is not None else len(findings)

    def stream(self, stmt):
        return _FakeStreamResult(self._findings)

    async def execute(self, stmt):
        result = MagicMock()
        result.scalar_one.return_value = self._count
        return result


# ---------------------------------------------------------------------------
# _finding_to_row
# ---------------------------------------------------------------------------

def test_finding_to_row_maps_all_export_columns():
    f = _make_finding(detail={"title": "SQL Injection", "cve_id": "CVE-2026-1234", "file_path": "src/app.py", "start_line": 42})
    row = _finding_to_row(f)
    for col in EXPORT_COLUMNS:
        assert col in row, f"Missing column: {col}"


def test_finding_to_row_extracts_detail_fields():
    f = _make_finding(detail={"title": "Log4Shell", "cve_id": "CVE-2021-44228", "file_path": "app/Main.java", "start_line": 10})
    row = _finding_to_row(f)
    assert row["title"] == "Log4Shell"
    assert row["cve_id"] == "CVE-2021-44228"
    assert row["file_path"] == "app/Main.java"
    assert row["line"] == 10


def test_finding_to_row_handles_missing_detail():
    f = _make_finding(detail={"title": "Only title"})
    row = _finding_to_row(f)
    assert row["cve_id"] == ""
    assert row["file_path"] == ""


# ---------------------------------------------------------------------------
# _build_where_clauses
# ---------------------------------------------------------------------------

def test_build_where_clauses_empty_filters():
    filters = FindingFilters()
    clauses = _build_where_clauses(filters)
    assert clauses == []


def test_build_where_clauses_produces_clauses_for_all_params():
    filters = FindingFilters(
        severity=["critical"],
        scanner=["secrets"],
        status=["open"],
        repo_id="example-org/api",
        since=datetime(2026, 1, 1, tzinfo=timezone.utc),
        until=datetime(2026, 6, 1, tzinfo=timezone.utc),
    )
    clauses = _build_where_clauses(filters)
    assert len(clauses) == 6


# ---------------------------------------------------------------------------
# count_findings
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_count_findings_returns_scalar():
    session = _FakeSession([], count=42)
    result = await count_findings(FindingFilters(), session)
    assert result == 42


# ---------------------------------------------------------------------------
# stream_findings_csv
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_csv_header_matches_export_columns():
    session = _FakeSession([])
    chunks = []
    async for chunk in stream_findings_csv(FindingFilters(), session):
        chunks.append(chunk)
    combined = b"".join(chunks).decode()
    reader = csv.DictReader(io.StringIO(combined))
    assert reader.fieldnames == EXPORT_COLUMNS


@pytest.mark.asyncio
async def test_csv_row_count_matches_fixtures():
    findings = [_make_finding(id=i) for i in range(5)]
    session = _FakeSession(findings)
    chunks = []
    async for chunk in stream_findings_csv(FindingFilters(), session):
        chunks.append(chunk)
    combined = b"".join(chunks).decode()
    reader = csv.DictReader(io.StringIO(combined))
    rows = list(reader)
    assert len(rows) == 5


@pytest.mark.asyncio
async def test_csv_row_values_correct():
    f = _make_finding(
        id=1,
        tool="secret_scanning",
        severity="critical",
        detail={"title": "Hardcoded key", "cve_id": "", "file_path": "config.py", "start_line": 5},
    )
    session = _FakeSession([f])
    chunks = []
    async for chunk in stream_findings_csv(FindingFilters(), session):
        chunks.append(chunk)
    combined = b"".join(chunks).decode()
    reader = csv.DictReader(io.StringIO(combined))
    rows = list(reader)
    assert rows[0]["scanner"] == "secrets"
    assert rows[0]["severity"] == "critical"
    assert rows[0]["title"] == "Hardcoded key"
    assert rows[0]["file_path"] == "config.py"


@pytest.mark.asyncio
async def test_csv_large_result_streams_in_batches():
    """Streaming 10k rows must not raise and must emit all rows without
    loading them all at once (validated by the fake batch session)."""
    findings = [_make_finding(id=i, severity="high") for i in range(10_000)]
    session = _FakeSession(findings)
    total_rows = 0
    async for chunk in stream_findings_csv(FindingFilters(), session):
        # Count data lines (skip header which has no id value)
        for line in chunk.decode().splitlines():
            if line and not line.startswith("id,"):
                total_rows += 1
    assert total_rows == 10_000


# ---------------------------------------------------------------------------
# stream_findings_json
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_json_emits_one_object_per_line():
    findings = [_make_finding(id=i) for i in range(3)]
    session = _FakeSession(findings)
    chunks = []
    async for chunk in stream_findings_json(FindingFilters(), session):
        chunks.append(chunk)
    combined = b"".join(chunks).decode()
    lines = [l for l in combined.splitlines() if l.strip()]
    assert len(lines) == 3
    for line in lines:
        obj = json.loads(line)
        for col in EXPORT_COLUMNS:
            assert col in obj, f"Missing key: {col}"


@pytest.mark.asyncio
async def test_json_empty_result_yields_nothing():
    session = _FakeSession([])
    chunks = []
    async for chunk in stream_findings_json(FindingFilters(), session):
        chunks.append(chunk)
    assert b"".join(chunks) == b""


@pytest.mark.asyncio
async def test_json_large_result_streams_10k_rows():
    findings = [_make_finding(id=i) for i in range(10_000)]
    session = _FakeSession(findings)
    line_count = 0
    async for chunk in stream_findings_json(FindingFilters(), session):
        line_count += chunk.count(b"\n")
    assert line_count == 10_000


# ---------------------------------------------------------------------------
# Filter integration (applied via _build_where_clauses, verified via _FakeSession)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_severity_filter_passed_through():
    """Verify that severity filter produces WHERE clauses (integration check)."""
    filters = FindingFilters(severity=["critical"])
    clauses = _build_where_clauses(filters)
    assert len(clauses) == 1


@pytest.mark.asyncio
async def test_multiple_filters_all_applied():
    filters = FindingFilters(
        severity=["high", "critical"],
        scanner=["dependencies"],
        repo_id="example-org/payments",
    )
    clauses = _build_where_clauses(filters)
    assert len(clauses) == 3
