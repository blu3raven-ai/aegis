"""Report generation service."""
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


def _storage_key(created_by: str, report_id: int, fmt: str) -> str:
    safe_owner = "".join(c if c.isalnum() or c in "-_" else "_" for c in created_by) or "unknown"
    return f"{safe_owner}/{report_id}.{fmt}"


def _auto_title(report_type: str, fmt: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"{report_type.capitalize()} report — {ts} ({fmt.upper()})"


async def _fetch_findings(
    session: AsyncSession,
    filters: dict | None,
    include_archived_rows: bool = False,
    *,
    asset_ids: list[str],
) -> list[dict]:
    if not asset_ids:
        return []
    stmt = select(Finding).where(Finding.asset_id.in_(asset_ids))
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


def _serialize_posture_json(asset_ids: list[str]) -> bytes:
    from src.posture.service import get_posture_snapshot
    payload = get_posture_snapshot(asset_ids=asset_ids)
    return json.dumps(asdict(payload), default=_json_default, indent=2).encode()


# Lazy-init so CSV/JSON-only test runs don't pay the Jinja import cost.
_jinja_env = None


def _get_jinja_env():
    global _jinja_env
    if _jinja_env is None:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        from src.exports.pdf import TEMPLATE_DIR
        _jinja_env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml", "j2"]),
        )
    return _jinja_env


def _finding_title(row: dict) -> str:
    if row.get("title"):
        return row["title"]
    tool = row.get("tool", "?")
    key = (row.get("identity_key") or "")[:80]
    return f"{tool}: {key}"


def _finding_source_label(row: dict) -> str:
    # Rows from _fetch_findings only expose _FINDING_FIELDS — no org/repo. The
    # source label here is intentionally minimal; per-asset hostname enrichment
    # can be layered later if needed.
    return row.get("tool") or "—"


def _build_findings_pdf_payload(
    *,
    title: str,
    rows: list[dict],
    scope_label: str,
) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings_out = []
    for r in rows:
        sev = (r.get("severity") or "").lower()
        if sev in counts:
            counts[sev] += 1
        findings_out.append({
            "severity": sev or None,
            "title": _finding_title(r),
            "source_label": _finding_source_label(r),
            "state": r.get("state") or "—",
        })

    return {
        "title": title,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scope_label": scope_label,
        "severity_counts": counts,
        "findings": findings_out,
    }


def _build_posture_pdf_payload(*, title: str, asset_ids: list[str]) -> dict:
    from src.posture.service import get_posture_snapshot

    payload = get_posture_snapshot(asset_ids=asset_ids)
    payload_dict = asdict(payload)
    return {
        "title": title,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "counts": payload_dict["counts"],
        "remediation": payload_dict["remediation"],
        "repository_coverage": payload_dict["repositoryCoverage"],
        "risk_score": payload_dict["riskScore"],
        "top_repositories": payload_dict["topRepositories"],
    }


def _serialize_findings_pdf(rows: list[dict], *, title: str, scope_label: str) -> bytes:
    from src.exports.pdf import render_pdf

    env = _get_jinja_env()
    html = env.get_template("report_findings.html.j2").render(
        **_build_findings_pdf_payload(title=title, rows=rows, scope_label=scope_label)
    )
    return render_pdf(html)


def _serialize_posture_pdf(*, asset_ids: list[str], title: str) -> bytes:
    from src.exports.pdf import render_pdf

    env = _get_jinja_env()
    html = env.get_template("report_posture.html.j2").render(
        **_build_posture_pdf_payload(title=title, asset_ids=asset_ids)
    )
    return render_pdf(html)


async def _mark_failed(session: AsyncSession, report_id: int, error: str) -> None:
    row = await session.get(Report, report_id)
    if row:
        row.status = "failed"
        row.error = error


def generate_report(
    report_type: str,
    fmt: str,
    title: str | None,
    filters: dict | None,
    created_by: str,
    include_archived: bool = False,
    *,
    asset_ids: list[str],
) -> Report:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=_RETENTION_DAYS)
    effective_title = title or _auto_title(report_type, fmt)

    if report_type == "findings":
        rows_data: list[dict] = run_db(
            lambda s: _fetch_findings(
                s, filters,
                include_archived_rows=include_archived,
                asset_ids=asset_ids,
            )
        )
        if fmt == "pdf":
            scope_label = f"{len(asset_ids)} assets in scope"
            content = _serialize_findings_pdf(
                rows_data, title=effective_title, scope_label=scope_label,
            )
            content_type = "application/pdf"
        elif fmt == "csv":
            content = _serialize_findings_csv(rows_data)
            content_type = "text/csv"
        else:
            content = _serialize_findings_json(rows_data)
            content_type = "application/json"
        row_count = len(rows_data)
    elif report_type == "posture":
        if fmt == "pdf":
            content = _serialize_posture_pdf(
                asset_ids=asset_ids, title=effective_title,
            )
            content_type = "application/pdf"
        elif fmt == "csv":
            raise ValueError("posture reports do not support csv format")
        else:
            content = _serialize_posture_json(asset_ids)
            content_type = "application/json"
        row_count = 1
    else:
        raise ValueError(f"Unknown report_type: {report_type!r}")

    persisted_filters: dict = dict(filters) if filters else {}
    if include_archived:
        persisted_filters["include_archived"] = True
    persisted_filters["asset_ids"] = list(asset_ids)

    async def _insert(session: AsyncSession) -> int:
        report = Report(
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

    key = _storage_key(created_by, report_id, fmt)
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


def _report_visible_to_viewer(report: Report, *, viewer_id: str, viewer_asset_ids: set[str]) -> bool:
    """Report visibility: creator always sees it; others if any of the report's
    persisted asset_ids intersects the viewer's accessible asset_ids.

    A report without persisted asset_ids (legacy rows) falls back to creator-only.
    """
    if report.created_by == viewer_id:
        return True
    persisted = (report.filters or {}).get("asset_ids")
    if not persisted:
        return False
    return bool(viewer_asset_ids.intersection(persisted))


def list_reports(
    viewer_id: str,
    viewer_asset_ids: list[str],
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Report], int]:
    """List reports visible to the viewer.

    The TeamAsset-intersection check runs in Python after fetching a window
    of candidate rows. Overshoot the limit to absorb post-filter exclusions —
    a 50-row response page reads up to a few hundred rows worst case, still
    cheap for the report volumes we expect.
    """
    scoped_assets = set(viewer_asset_ids)
    fetch_window = max((limit + offset) * 4, 200)

    async def _query(session: AsyncSession) -> tuple[list[Report], int]:
        rows = (await session.execute(
            select(Report)
            .order_by(Report.created_at.desc())
            .limit(fetch_window)
        )).scalars().all()
        visible = [
            r for r in rows
            if _report_visible_to_viewer(r, viewer_id=viewer_id, viewer_asset_ids=scoped_assets)
        ]
        return visible[offset:offset + limit], len(visible)

    return run_db(_query)


def get_report(report_id: int, viewer_id: str, viewer_asset_ids: list[str]) -> Report | None:
    scoped_assets = set(viewer_asset_ids)

    async def _query(session: AsyncSession) -> Report | None:
        row = await session.get(Report, report_id)
        if not row:
            return None
        if not _report_visible_to_viewer(row, viewer_id=viewer_id, viewer_asset_ids=scoped_assets):
            return None
        return row
    return run_db(_query)


def delete_report(report_id: int, viewer_id: str, viewer_asset_ids: list[str]) -> bool:
    scoped_assets = set(viewer_asset_ids)

    async def _delete(session: AsyncSession) -> tuple[str | None, bool]:
        row = await session.get(Report, report_id)
        if not row:
            return None, False
        if not _report_visible_to_viewer(row, viewer_id=viewer_id, viewer_asset_ids=scoped_assets):
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
