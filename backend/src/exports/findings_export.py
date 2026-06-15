"""Streaming findings export — CSV and JSONL.

Yields bytes in batches to avoid loading the entire result set into memory.
Both generators accept a FindingFilters dataclass and an AsyncSession so that
callers (the router) can compose filters without duplicating query logic.
"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Finding
from src.shared.archived_filter import exclude_archived, include_archived
from src.shared.scope import apply_scope

# Columns emitted in every export — ordered for human readability.
EXPORT_COLUMNS = [
    "id",
    "severity",
    "scanner",
    "title",
    "cve_id",
    "repo",
    "file_path",
    "line",
    "first_seen_at",
    "last_seen_at",
    "status",
    "assignee",
]

_BATCH_SIZE = 500


@dataclass
class FindingFilters:
    """Filter parameters accepted by both the router and the stream functions."""

    severity: list[str] | None = None
    scanner: list[str] | None = None
    status: list[str] | None = None
    repo_id: str | None = None
    since: datetime | None = None
    until: datetime | None = None


def _build_where_clauses(filters: FindingFilters) -> list:
    """Return a list of SQLAlchemy WHERE predicates for the given filters."""
    clauses = []
    if filters.severity:
        clauses.append(Finding.severity.in_(filters.severity))
    if filters.scanner:
        clauses.append(Finding.tool.in_(filters.scanner))
    if filters.status:
        clauses.append(Finding.state.in_(filters.status))
    if filters.repo_id:
        # repo_id is the human-readable Asset.display_name (e.g. "acme/foo")
        clauses.append(
            Finding.asset_id.in_(
                select(Asset.id).where(Asset.display_name == filters.repo_id)
            )
        )
    if filters.since:
        clauses.append(Finding.first_seen_at >= filters.since)
    if filters.until:
        clauses.append(Finding.first_seen_at <= filters.until)
    return clauses


def _finding_to_row(finding: Finding) -> dict[str, Any]:
    """Map a Finding ORM row to the flat export dict."""
    detail: dict = finding.detail or {}
    return {
        "id": finding.id,
        "severity": finding.severity or "",
        "scanner": finding.tool,
        "title": finding.title or finding.identity_key,
        "cve_id": finding.cve_id or "",
        "repo": finding.repo or "",
        "file_path": finding.file_path or "",
        "line": detail.get("start_line") or detail.get("line") or "",
        "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else "",
        "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else "",
        "status": finding.state,
        "assignee": detail.get("assignee") or "",
    }


async def count_findings(
    filters: FindingFilters,
    asset_ids: list[str],
    session: AsyncSession,
    include_archived_rows: bool = False,
) -> int:
    """Return the total number of findings matching the filters."""
    where = _build_where_clauses(filters)
    stmt = select(func.count()).select_from(Finding)
    if where:
        stmt = stmt.where(and_(*where))
    stmt = apply_scope(stmt, asset_ids, column=Finding.asset_id)
    if include_archived_rows:
        stmt = include_archived(stmt)
    else:
        stmt = exclude_archived(stmt, Finding)
    result = await session.execute(stmt)
    return result.scalar_one()


async def stream_findings_csv(
    filters: FindingFilters,
    asset_ids: list[str],
    session: AsyncSession,
    include_archived_rows: bool = False,
) -> AsyncIterator[bytes]:
    """Yield CSV bytes — header first, then rows streamed in batches of 500."""
    # Emit the header row first so clients can begin parsing immediately.
    header_buf = io.StringIO()
    writer = csv.DictWriter(header_buf, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    yield header_buf.getvalue().encode()

    where = _build_where_clauses(filters)
    stmt = select(Finding).order_by(Finding.id)
    if where:
        stmt = stmt.where(and_(*where))
    stmt = apply_scope(stmt, asset_ids, column=Finding.asset_id)
    # Same default-exclude contract as the /findings list and reports — archived
    # rows are hidden unless the caller explicitly opts in.
    if include_archived_rows:
        stmt = include_archived(stmt)
    else:
        stmt = exclude_archived(stmt, Finding)

    async with session.stream(stmt) as result:
        async for partition in result.partitions(_BATCH_SIZE):
            batch_buf = io.StringIO()
            batch_writer = csv.DictWriter(batch_buf, fieldnames=EXPORT_COLUMNS, extrasaction="ignore")
            for row in partition:
                batch_writer.writerow(_finding_to_row(row.Finding))
            chunk = batch_buf.getvalue()
            if chunk:
                yield chunk.encode()


async def stream_findings_json(
    filters: FindingFilters,
    asset_ids: list[str],
    session: AsyncSession,
    include_archived_rows: bool = False,
) -> AsyncIterator[bytes]:
    """Yield newline-delimited JSON (JSONL) bytes — one finding per line.

    JSONL is preferred over a JSON array because consumers can parse one record
    at a time without buffering the entire response body.
    """
    where = _build_where_clauses(filters)
    stmt = select(Finding).order_by(Finding.id)
    if where:
        stmt = stmt.where(and_(*where))
    stmt = apply_scope(stmt, asset_ids, column=Finding.asset_id)
    if include_archived_rows:
        stmt = include_archived(stmt)
    else:
        stmt = exclude_archived(stmt, Finding)

    async with session.stream(stmt) as result:
        async for partition in result.partitions(_BATCH_SIZE):
            for row in partition:
                line = json.dumps(_finding_to_row(row.Finding), default=str) + "\n"
                yield line.encode()
