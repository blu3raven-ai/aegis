"""REST endpoints for bulk findings export — Phase 49.

GET /api/v1/exports/findings
    Stream findings as CSV or JSONL with optional filters.

The response is a streaming download — rows are emitted in batches to keep
memory overhead constant regardless of result set size.  A COUNT query runs
first so the X-Total-Count header can be set before streaming begins.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from src.db.engine import get_session
from src.exports.findings_export import (
    FindingFilters,
    count_findings,
    stream_findings_csv,
    stream_findings_json,
)
from src.settings.router import require_permission
from src.shared.scope import resolve_asset_ids_from_request

router = APIRouter(prefix="/api/v1/exports", tags=["exports"])


def _parse_csv_list(value: str | None) -> list[str] | None:
    """Split a comma-separated query param into a list, or return None."""
    if not value:
        return None
    return [v.strip() for v in value.split(",") if v.strip()]


def _filename(fmt: str, ts: datetime) -> str:
    stamp = ts.strftime("%Y-%m-%dT%H%M")
    return f"aegis-findings-{stamp}.{fmt if fmt == 'csv' else 'jsonl'}"


@router.get("/findings")
async def export_findings(
    request: Request,
    format: Literal["csv", "json"] = Query(default="csv", description="Output format: csv or json (JSONL)"),
    severity: str | None = Query(default=None, description="Comma-separated severities (critical,high,medium,low)"),
    scanner: str | None = Query(default=None, description="Comma-separated scanner types (e.g. dependencies,secrets)"),
    status: str | None = Query(default=None, description="Comma-separated finding states (open,fixed,dismissed)"),
    repo_id: str | None = Query(default=None, description="Filter to a single repository (owner/name)"),
    since: datetime | None = Query(default=None, description="Only findings first seen on or after this ISO-8601 timestamp"),
    until: datetime | None = Query(default=None, description="Only findings first seen on or before this ISO-8601 timestamp"),
    include_archived: bool = Query(default=False, description="Include archived findings (compliance opt-in). Defaults to excluding archived rows."),
) -> StreamingResponse:
    """Stream findings as a downloadable CSV or JSONL file.

    Uses server-side streaming so large exports never load the full result set
    into memory.  The X-Total-Count response header contains the matching row
    count, useful for progress indicators in CLI clients.
    """
    require_permission(request, "view_findings")
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
