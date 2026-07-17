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

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Asset, Finding
from src.shared.archived_filter import exclude_archived, include_archived
from src.authz.enforcement.scope import apply_scope

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


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: Any) -> Any:
    """Prefix string cells that start with formula-trigger characters."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _finding_to_row(finding: Finding) -> dict[str, Any]:
    """Map a Finding ORM row to the flat export dict."""
    detail: dict = finding.detail or {}
    row = {
        "id": finding.id,
        "severity": finding.severity or "",
        "scanner": finding.tool,
        "title": finding.title or finding.identity_key,
        "cve_id": finding.cve_id or "",
        "repo": getattr(finding, "repo", None) or "",
        "file_path": finding.file_path or "",
        "line": detail.get("start_line") or detail.get("line") or "",
        "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else "",
        "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else "",
        "status": finding.state,
        "assignee": detail.get("assignee") or "",
    }
    return {k: _sanitize_csv_cell(v) for k, v in row.items()}


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


# SARIF 2.1.0 severity mapping. `level` is the qualitative result level GitHub
# code scanning renders; `security-severity` is the numeric (CVSS-like) string it
# sorts and gates branch-protection on. Both live in the SARIF spec / GitHub's
# ingestion contract.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}
_SARIF_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
    "info": "1.0",
    "informational": "1.0",
}


def _sarif_level(severity: str | None) -> str:
    return _SARIF_LEVEL.get((severity or "").lower(), "warning")


def _sarif_security_severity(severity: str | None) -> str:
    return _SARIF_SECURITY_SEVERITY.get((severity or "").lower(), "0.0")


def _sarif_rule_id(finding: Finding) -> str:
    """Stable rule identity GitHub groups results under.

    A CVE is the most meaningful grouping for SCA/container findings; SAST/secret
    findings fall back to their rule name, then the scanner as a last resort.
    """
    return finding.cve_id or finding.rule_name or finding.tool


def _finding_to_sarif_result(
    finding: Finding, rules_index: dict[str, int], rules: list[dict[str, Any]]
) -> dict[str, Any]:
    """Map a Finding to a SARIF result, registering its rule on first sight."""
    rule_id = _sarif_rule_id(finding)
    sec = _sarif_security_severity(finding.severity)

    if rule_id not in rules_index:
        rules_index[rule_id] = len(rules)
        rules.append({
            "id": rule_id,
            "name": finding.rule_name or finding.tool or rule_id,
            "shortDescription": {"text": finding.title or rule_id},
            "properties": {"tags": ["security", finding.tool], "security-severity": sec},
        })
    else:
        # A rule's severity is the worst across the findings that share it.
        props = rules[rules_index[rule_id]]["properties"]
        if float(sec) > float(props.get("security-severity", "0.0")):
            props["security-severity"] = sec

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rules_index[rule_id],
        "level": _sarif_level(finding.severity),
        "message": {"text": finding.title or finding.identity_key},
        "partialFingerprints": {"aegisIdentityKey": finding.identity_key},
        "properties": {
            "severity": finding.severity or "",
            "scanner": finding.tool,
            "security-severity": sec,
        },
    }
    if finding.cve_id:
        result["properties"]["cve"] = finding.cve_id

    if finding.file_path:
        detail: dict = finding.detail or {}
        physical: dict[str, Any] = {"artifactLocation": {"uri": finding.file_path}}
        line = detail.get("start_line") or detail.get("line")
        if isinstance(line, int) and line > 0:
            physical["region"] = {"startLine": line}
        result["locations"] = [{"physicalLocation": physical}]

    return result


async def stream_findings_sarif(
    filters: FindingFilters,
    asset_ids: list[str],
    session: AsyncSession,
    include_archived_rows: bool = False,
) -> AsyncIterator[bytes]:
    """Stream a SARIF 2.1.0 document as bytes.

    SARIF is the OASIS standard that GitHub/GitLab code scanning ingest. The
    findings are streamed into the ``results`` array so the full set never
    buffers in memory; the ``rules`` array is bounded by the number of distinct
    rule types and is emitted after ``results`` (JSON key order is irrelevant to
    consumers). Scope + the default-exclude-archived contract match the other
    export formats exactly.
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

    rules_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []

    yield (
        b'{"$schema":"https://json.schemastore.org/sarif-2.1.0.json",'
        b'"version":"2.1.0","runs":[{"results":['
    )
    first = True
    result = await session.stream(stmt)
    async for partition in result.partitions(_BATCH_SIZE):
        for row in partition:
            sarif = _finding_to_sarif_result(row.Finding, rules_index, rules)
            chunk = json.dumps(sarif, separators=(",", ":"), default=str).encode()
            yield chunk if first else b"," + chunk
            first = False
    yield (
        b'],"tool":{"driver":{"name":"Aegis","rules":'
        + json.dumps(rules, separators=(",", ":"), default=str).encode()
        + b"}}}]}"
    )


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
