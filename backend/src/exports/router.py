"""REST endpoints for bulk findings export — Phase 49.

GET /api/v1/findings/export
    Stream findings as CSV or JSONL with optional filters.

The response is a streaming download — rows are emitted in batches to keep
memory overhead constant regardless of result set size.  A COUNT query runs
first so the X-Total-Count header can be set before streaming begins.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from src.db.engine import get_session
from src.exports.findings_export import (
    FindingFilters,
    count_findings,
    stream_findings_csv,
    stream_findings_json,
    stream_findings_sarif,
)
from src.authz.enforcement.dependencies import Permission
from src.authz.enforcement.scope import resolve_asset_ids_from_request
from src.authz.permissions.catalog import VIEW_FINDINGS

router = APIRouter(prefix="/api/v1/findings", tags=["findings"])


def _parse_csv_list(value: str | None) -> list[str] | None:
    """Split a comma-separated query param into a list, or return None."""
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


_EXTENSIONS = {"csv": "csv", "json": "jsonl", "sarif": "sarif"}


def _filename(fmt: str, ts: datetime) -> str:
    stamp = ts.strftime("%Y-%m-%dT%H%M")
    return f"aegis-findings-{stamp}.{_EXTENSIONS.get(fmt, 'txt')}"


@router.get("/export")
async def export_findings(
    request: Request,
    format: Literal["csv", "json", "sarif"] = Query(default="csv", description="Output format: csv, json (JSONL), or sarif (SARIF 2.1.0)"),
    severity: str | None = Query(default=None, description="Comma-separated severities (critical,high,medium,low)"),
    scanner: str | None = Query(default=None, description="Comma-separated scanner types (e.g. dependencies,secrets)"),
    status: str | None = Query(default=None, description="Comma-separated finding states (open,fixed,dismissed)"),
    repo_id: str | None = Query(default=None, description="Filter to a single repository (owner/name)"),
    since: datetime | None = Query(default=None, description="Only findings first seen on or after this ISO-8601 timestamp"),
    until: datetime | None = Query(default=None, description="Only findings first seen on or before this ISO-8601 timestamp"),
    include_archived: bool = Query(default=False, description="Include archived findings (compliance opt-in). Defaults to excluding archived rows."),
    _: None = Depends(Permission(VIEW_FINDINGS)),
) -> StreamingResponse:
    """Stream findings as a downloadable CSV or JSONL file.

    Uses server-side streaming so large exports never load the full result set
    into memory.  The X-Total-Count response header contains the matching row
    count, useful for progress indicators in CLI clients.
    """
    asset_ids = await resolve_asset_ids_from_request(request)

    filters = FindingFilters(
        severity=_parse_csv_list(severity),
        scanner=_parse_csv_list(scanner),
        status=_parse_csv_list(status),
        repo_id=repo_id,
        since=since,
        until=until,
    )

    now = datetime.now(timezone.utc)
    filename = _filename(format, now)

    async with get_session() as session:
        total = await count_findings(filters, asset_ids, session, include_archived_rows=include_archived)

    if format == "sarif":
        # SARIF is one JSON document, but its results array is streamed so a
        # large export never buffers the full finding set in memory. It is the
        # format CI/code-scanning dashboards (GitHub, GitLab) ingest.
        async def _generate_sarif():
            async with get_session() as session:
                async for chunk in stream_findings_sarif(filters, asset_ids, session, include_archived_rows=include_archived):
                    yield chunk

        return StreamingResponse(
            _generate_sarif(),
            media_type="application/sarif+json",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Total-Count": str(total),
            },
        )

    if format == "csv":
        content_type = "text/csv"

        async def _generate():
            async with get_session() as session:
                async for chunk in stream_findings_csv(filters, asset_ids, session, include_archived_rows=include_archived):
                    yield chunk

        return StreamingResponse(
            _generate(),
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Total-Count": str(total),
            },
        )
    else:
        content_type = "application/x-ndjson"

        async def _generate():
            async with get_session() as session:
                async for chunk in stream_findings_json(filters, asset_ids, session, include_archived_rows=include_archived):
                    yield chunk

        return StreamingResponse(
            _generate(),
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Total-Count": str(total),
            },
        )
