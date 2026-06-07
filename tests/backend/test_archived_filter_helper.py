"""Unit tests for the archived-filter helpers.

These tests are pure SQLAlchemy expression construction — no DB round-trip
required. They lock in the contract that ``exclude_archived`` appends a
``archived = false`` predicate and ``include_archived`` is a no-op marker.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from src.db.models import Finding, ScanRun
from src.shared.archived_filter import exclude_archived, include_archived, only_archived


def _render(stmt) -> str:
    return str(stmt.compile(
        dialect=postgresql.dialect(),
        compile_kwargs={"literal_binds": True},
    ))


def test_exclude_archived_appends_filter_for_finding():
    stmt = select(Finding)
    filtered = exclude_archived(stmt, Finding)
    sql = _render(filtered).lower()
    assert "findings.archived = false" in sql


def test_exclude_archived_appends_filter_for_scan_run():
    stmt = select(ScanRun)
    filtered = exclude_archived(stmt, ScanRun)
    sql = _render(filtered).lower()
    assert "scan_runs.archived = false" in sql


def test_exclude_archived_preserves_existing_where_clauses():
    stmt = select(Finding).where(Finding.org == "acme-org")
    filtered = exclude_archived(stmt, Finding)
    sql = _render(filtered).lower()
    assert "findings.org = 'acme-org'" in sql
    assert "findings.archived = false" in sql


def test_include_archived_is_passthrough():
    stmt = select(Finding).where(Finding.org == "acme-org")
    marker = include_archived(stmt)
    assert marker is stmt
    # The marker must not append any predicate — the rendered WHERE clause
    # is identical to what we passed in.
    sql_in = _render(stmt).lower()
    sql_out = _render(marker).lower()
    assert sql_in == sql_out
    assert "archived = false" not in sql_out


def test_only_archived_appends_filter():
    stmt = select(Finding).where(Finding.org == "acme-org")
    filtered = only_archived(stmt, Finding)
    sql = _render(filtered).lower()
    assert "findings.org = 'acme-org'" in sql
    assert "findings.archived = true" in sql
    # only_archived must NOT add the exclude predicate.
    assert "findings.archived = false" not in sql


def test_only_archived_for_scan_run():
    stmt = select(ScanRun)
    filtered = only_archived(stmt, ScanRun)
    sql = _render(filtered).lower()
    assert "scan_runs.archived = true" in sql
