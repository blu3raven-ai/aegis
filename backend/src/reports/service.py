"""Report generation service: sync, stores output in MinIO reports bucket."""
from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import false as sa_false, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Finding, Report
from src.shared.archived_filter import exclude_archived, include_archived
from src.shared.object_store import delete_prefix, generate_download_url, upload_bytes

logger = logging.getLogger(__name__)

_REPORTS_BUCKET = "reports"
_RETENTION_DAYS = 30
_DOWNLOAD_URL_TTL = 1800

_FINDING_FIELDS = [
    "id", "tool", "asset_id", "severity", "state",
    "title", "identity_key", "cve_id", "first_seen_at", "last_seen_at",
]


def _storage_key(org: str, report_id: int, fmt: str) -> str:
    return f"{org}/{report_id}.{fmt}"


def _auto_title(report_type: str, fmt: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"{report_type.capitalize()} report — {ts} ({fmt.upper()})"


async def _fetch_findings(
    session: AsyncSession,
    org: str | None,
    filters: dict | None,
    include_archived_rows: bool = False,
    *,
    asset_ids: list[str] | None = None,
) -> list[dict]:
    if asset_ids is not None and not asset_ids:
        return []
    if asset_ids is not None:
        stmt = select(Finding).where(Finding.asset_id.in_(asset_ids))
    else:
        # Org-only callers no longer have a scope after Plan D; fail closed.
        stmt = select(Finding).where(sa_false())
    if filters:
        if filters.get("severity"):
            stmt = stmt.where(Finding.severity.in_(filters["severity"]))
        if filters.get("scanner"):
            stmt = stmt.where(Finding.tool.in_(filters["scanner"]))
        if filters.get("state"):
            stmt = stmt.where(Finding.state.in_(filters["state"]))
        if filters.get("repo"):
            from src.db.models import Asset
            stmt = stmt.where(
                Finding.asset_id.in_(
                    select(Asset.id).where(Asset.display_name == filters["repo"])
                )
            )
    # Compliance flows pass include_archived=True to emit the full archive
    # tail. Default report runs exclude archived rows like every other
    # user-facing read path.
    if include_archived_rows:
        stmt = include_archived(stmt)
    else:
        stmt = exclude_archived(stmt, Finding)
    rows = (await session.execute(stmt)).scalars().all()
    return [{f: getattr(row, f, None) for f in _FINDING_FIELDS} for row in rows]


def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _serialize_findings_json(rows: list[dict]) -> bytes:
    return json.dumps(rows, default=_json_default, indent=2).encode()


def _serialize_findings_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FINDING_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            k: (v.isoformat() if isinstance(v, datetime) else v)
            for k, v in row.items()
        })
    return buf.getvalue().encode()


def _serialize_posture_json(org: str) -> bytes:
    from src.posture.service import get_posture_snapshot
    payload = get_posture_snapshot(org=org)
    return json.dumps(asdict(payload), default=_json_default, indent=2).encode()


async def _mark_failed(session: AsyncSession, report_id: int, error: str) -> None:
    row = await session.get(Report, report_id)
    if row:
        row.status = "failed"
        row.error = error


def generate_report(
    org: str,
    report_type: str,
    fmt: str,
    title: str | None,
    filters: dict | None,
    created_by: str,
    include_archived: bool = False,
    *,
    asset_ids: list[str] | None = None,
) -> Report:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=_RETENTION_DAYS)
    effective_title = title or _auto_title(report_type, fmt)

    if report_type == "findings":
        rows_data: list[dict] = run_db(
            lambda s: _fetch_findings(
                s, org, filters,
                include_archived_rows=include_archived,
                asset_ids=asset_ids,
            )
        )
        if fmt == "csv":
            content = _serialize_findings_csv(rows_data)
            content_type = "text/csv"
        else:
            content = _serialize_findings_json(rows_data)
            content_type = "application/json"
        row_count = len(rows_data)
    elif report_type == "posture":
        # Posture is always current-state — there is no compliance flow that
        # asks for "posture including archived findings". The flag is ignored.
        content = _serialize_posture_json(org)
        content_type = "application/json"
        row_count = 1
    else:
        raise ValueError(f"Unknown report_type: {report_type!r}")

    # Persist the include_archived choice on the report row so the audit
    # trail records which reports surfaced archived data — compliance teams
    # can later prove a report's row scope by inspecting Report.filters.
    persisted_filters: dict | None = dict(filters) if filters else None
    if include_archived:
        persisted_filters = persisted_filters or {}
        persisted_filters["include_archived"] = True

    async def _insert(session: AsyncSession) -> int:
        report = Report(
            org=org,
            title=effective_title,
            report_type=report_type,
            format=fmt,
            status="pending",
            filters=persisted_filters,
            row_count=row_count,
            file_size_bytes=len(content),
            created_by=created_by,
            expires_at=expires_at,
        )
        session.add(report)
        await session.flush()
        return report.id

    report_id: int = run_db(_insert)

    key = _storage_key(org, report_id, fmt)
    try:
        upload_bytes(key=key, data=content, content_type=content_type, bucket=_REPORTS_BUCKET)
    except Exception:
        logger.exception("Failed to upload report %s to MinIO", report_id)
        try:
            run_db(lambda s: _mark_failed(s, report_id, "MinIO upload failed"))
        except Exception:
            logger.exception("Failed to mark report %s as failed", report_id)
        raise

    async def _complete(session: AsyncSession) -> Report:
        row = await session.get(Report, report_id)
        if row is None:
            raise RuntimeError(f"Report {report_id} disappeared before completion")
        row.status = "completed"
        row.storage_key = key
        return row

    return run_db(_complete)


def list_reports(org: str, limit: int = 50, offset: int = 0) -> tuple[list[Report], int]:
    async def _query(session: AsyncSession) -> tuple[list[Report], int]:
        total = (await session.execute(
            select(func.count()).select_from(Report).where(Report.org == org)
        )).scalar_one()
        rows = (await session.execute(
            select(Report).where(Report.org == org)
            .order_by(Report.created_at.desc())
            .limit(limit).offset(offset)
        )).scalars().all()
        return list(rows), total
    return run_db(_query)


def get_report(report_id: int, org: str) -> Report | None:
    async def _query(session: AsyncSession) -> Report | None:
        row = await session.get(Report, report_id)
        if row and row.org == org:
            return row
        return None
    return run_db(_query)


def delete_report(report_id: int, org: str) -> bool:
    async def _delete(session: AsyncSession) -> tuple[str | None, bool]:
        row = await session.get(Report, report_id)
        if not row or row.org != org:
            return None, False
        key = row.storage_key
        await session.delete(row)
        return key, True

    key, deleted = run_db(_delete)
    if deleted and key:
        try:
            delete_prefix(prefix=key, bucket=_REPORTS_BUCKET)
        except Exception:
            logger.warning("Failed to delete MinIO object %s for report %s", key, report_id)
    return deleted


def get_download_url(report: Report) -> str | None:
    if not report.storage_key or report.status != "completed":
        return None
    try:
        return generate_download_url(
            key=report.storage_key,
            expires_in=_DOWNLOAD_URL_TTL,
            bucket=_REPORTS_BUCKET,
        )
    except Exception:
        logger.warning("Failed to generate download URL for report %s", report.id)
        return None
