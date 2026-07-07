"""Report generation service."""
from __future__ import annotations

import csv
import io
import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
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


_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_csv_cell(value: object) -> object:
    """Prefix string cells that start with formula-trigger characters."""
    if isinstance(value, str) and value.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _serialize_findings_csv(rows: list[dict]) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FINDING_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            k: _sanitize_csv_cell(v.isoformat() if isinstance(v, datetime) else v)
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


_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


async def _fetch_top_open_findings(
    session: AsyncSession, asset_ids: list[str], *, limit: int = 10
) -> list[dict]:
    """The most urgent open critical/high findings — worst severity, then oldest.

    Capped at 200 rows pre-sort so the executive report never scans an entire
    finding table; for the headline list that ceiling is never the binding
    constraint.
    """
    if not asset_ids:
        return []
    now = datetime.now(timezone.utc)
    stmt = (
        select(Finding)
        .where(Finding.asset_id.in_(asset_ids))
        .where(Finding.state == "open")
        .where(Finding.severity.in_(["critical", "high"]))
        .order_by(Finding.first_seen_at.asc())
        .limit(200)
    )
    stmt = exclude_archived(stmt, Finding)
    rows = (await session.execute(stmt)).scalars().all()
    ranked = sorted(
        rows,
        key=lambda r: (_SEV_RANK.get((r.severity or "").lower(), 4), r.first_seen_at or now),
    )
    out: list[dict] = []
    for r in ranked[:limit]:
        age_days = (now - r.first_seen_at).days if r.first_seen_at else None
        out.append({
            "severity": (r.severity or "").lower() or None,
            "title": _finding_title({"title": r.title, "tool": r.tool, "identity_key": r.identity_key}),
            "source_label": r.tool or "—",
            "age_days": age_days,
        })
    return out


def _sparkline_points(values: list[int], *, width: int = 480, height: int = 44) -> str:
    """Map a series to an SVG polyline `points` string for an inline sparkline."""
    if not values:
        return ""
    if len(values) == 1:
        y = height / 2
        return f"0,{y:.1f} {width},{y:.1f}"
    vmin, vmax = min(values), max(values)
    span = (vmax - vmin) or 1
    step = width / (len(values) - 1)
    return " ".join(
        f"{i * step:.1f},{height - ((v - vmin) / span) * height:.1f}"
        for i, v in enumerate(values)
    )


def _build_executive_pdf_payload(*, title: str, asset_ids: list[str]) -> dict:
    """Assemble the CISO-facing executive summary: KPIs, 30-day trend delta,
    remediation/MTTR, coverage, top repositories, and the most urgent findings."""
    from src.posture.service import get_posture_snapshot, get_posture_trend

    snapshot = asdict(get_posture_snapshot(asset_ids=asset_ids))
    trend = get_posture_trend(asset_ids=asset_ids, days=30)
    top_findings = run_db(lambda s: _fetch_top_open_findings(s, asset_ids))

    counts = snapshot["counts"]
    # Trend is oldest-first; the delta is open findings now vs the window start.
    open_30d_ago = trend[0]["total"] if trend else counts["total"]
    open_delta = counts["total"] - open_30d_ago

    return {
        "title": title,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scope_label": f"{len(asset_ids)} assets in scope",
        "period_label": "Last 30 days",
        "risk_score": snapshot["riskScore"],
        "counts": counts,
        "open_delta": open_delta,
        "open_30d_ago": open_30d_ago,
        "remediation": snapshot["remediation"],
        "repository_coverage": snapshot["repositoryCoverage"],
        "top_repositories": snapshot["topRepositories"],
        "top_findings": top_findings,
        "trend": trend,
        "trend_sparkline": _sparkline_points([p["total"] for p in trend]),
    }


def _serialize_executive_pdf(*, asset_ids: list[str], title: str) -> bytes:
    from src.exports.pdf import render_pdf

    env = _get_jinja_env()
    html = env.get_template("report_executive.html.j2").render(
        **_build_executive_pdf_payload(title=title, asset_ids=asset_ids)
    )
    return render_pdf(html)


_RISK_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


async def _fetch_risk_register(session: AsyncSession, asset_ids: list[str]) -> dict:
    """Open findings grouped by severity plus the accepted-risk (dismissed) log.

    The accepted-risk log is what compliance auditors look for: risks a human
    explicitly chose to accept, with the rationale. It joins each dismissed
    finding to its decision row for the reason.
    """
    from src.db.models import Decision

    now = datetime.now(timezone.utc)
    if not asset_ids:
        return {"open_by_severity": {}, "accepted": [], "open_count": 0, "accepted_count": 0}

    def _age(f) -> int | None:
        return (now - f.first_seen_at).days if f.first_seen_at else None

    open_stmt = exclude_archived(
        select(Finding)
        .where(Finding.asset_id.in_(asset_ids))
        .where(Finding.state.in_(("open", "deferred"))),
        Finding,
    )
    open_rows = (await session.execute(open_stmt)).scalars().all()
    by_sev: dict[str, list[dict]] = {}
    for f in open_rows:
        sev = (f.severity or "info").lower()
        by_sev.setdefault(sev, []).append({
            "title": _finding_title({"title": f.title, "tool": f.tool, "identity_key": f.identity_key}),
            "source": f.tool,
            "age_days": _age(f),
            "state": f.state,
        })
    for bucket in by_sev.values():
        bucket.sort(key=lambda r: (r["age_days"] is None, -(r["age_days"] or 0)))
    open_by_severity = {s: by_sev[s] for s in _RISK_SEVERITY_ORDER if s in by_sev}

    # Accepted risk = dismissed findings (incl. archived — it's an audit log) with
    # their decision rationale. One decision per finding via the unique key.
    acc_stmt = (
        select(Finding, Decision.reason, Decision.decided_by)
        .outerjoin(
            Decision,
            (Decision.tool == Finding.tool)
            & (Decision.asset_id == Finding.asset_id)
            & (Decision.identity_key == Finding.identity_key),
        )
        .where(Finding.asset_id.in_(asset_ids))
        .where(Finding.state == "dismissed")
    )
    accepted = []
    for f, reason, decided_by in (await session.execute(acc_stmt)).all():
        accepted.append({
            "severity": (f.severity or "info").lower(),
            "title": _finding_title({"title": f.title, "tool": f.tool, "identity_key": f.identity_key}),
            "source": f.tool,
            "reason": reason or "—",
            "decided_by": decided_by or "—",
            "age_days": _age(f),
        })

    return {
        "open_by_severity": open_by_severity,
        "accepted": accepted,
        "open_count": len(open_rows),
        "accepted_count": len(accepted),
    }


def _build_risk_register_payload(*, title: str, asset_ids: list[str]) -> dict:
    data = run_db(lambda s: _fetch_risk_register(s, asset_ids))
    return {
        "title": title,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scope_label": f"{len(asset_ids)} assets in scope",
        **data,
    }


def _serialize_risk_register_pdf(*, asset_ids: list[str], title: str) -> bytes:
    from src.exports.pdf import render_pdf

    env = _get_jinja_env()
    html = env.get_template("report_risk_register.html.j2").render(
        **_build_risk_register_payload(title=title, asset_ids=asset_ids)
    )
    return render_pdf(html)


_RISK_CSV_FIELDS = ["severity", "state", "title", "source", "age_days", "reason"]


def _serialize_risk_register_csv(*, asset_ids: list[str]) -> bytes:
    payload = _build_risk_register_payload(title="", asset_ids=asset_ids)
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_RISK_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for sev, rows in payload["open_by_severity"].items():
        for r in rows:
            writer.writerow({
                "severity": sev, "state": r["state"], "title": r["title"],
                "source": r["source"], "age_days": r["age_days"], "reason": "",
            })
    for r in payload["accepted"]:
        writer.writerow({
            "severity": r["severity"], "state": "dismissed", "title": r["title"],
            "source": r["source"], "age_days": r["age_days"], "reason": r["reason"],
        })
    return buf.getvalue().encode()


async def _mark_failed(session: AsyncSession, report_id: int, error: str) -> None:
    row = await session.get(Report, report_id)
    if row:
        row.status = "failed"
        row.error = error


def _serialize_soc2_evidence_zip(*, asset_ids: list[str], title: str) -> bytes:
    """Bundle a SOC 2 audit evidence pack as a ZIP.

    Auditors want a single artifact tying controls to their evidence and the
    risk decisions behind them. Packs three CSVs + a manifest:
      controls.csv        — each control's effective status, attestation, evidence
      mapped_findings.csv — the open findings substantiating each control's state
      accepted_risks.csv  — dismissed findings + the rationale (decision trail)
    """
    import zipfile

    from src.compliance.service import (
        _derive_control_status,
        get_findings_for_control,
        get_framework_summary,
    )

    async def _gather(session) -> dict:
        summary = await get_framework_summary(session, "soc2", asset_ids=asset_ids)
        controls: list[dict] = []
        mapped: list[dict] = []
        for item in summary:
            controls.append({
                "control_id": item.control_id,
                "title": item.title,
                "category": item.category or "",
                "status": _derive_control_status(item),
                "manual_status": item.manual_status or "",
                "evidence_note": item.evidence_note or "",
                "assessed_by": item.assessed_by or "",
                "assessed_at": item.assessed_at or "",
                "open_findings": item.finding_count,
            })
            if item.finding_count:
                for b in await get_findings_for_control(
                    session, "soc2", item.control_id, asset_ids=asset_ids
                ):
                    mapped.append({
                        "control_id": item.control_id,
                        "tool": b.tool,
                        "severity": b.severity or "",
                        "state": b.state,
                        "identity_key": b.identity_key,
                        "rationale": b.rationale or "",
                    })
        risk = await _fetch_risk_register(session, asset_ids)
        return {"controls": controls, "mapped": mapped, "accepted": risk["accepted"]}

    data = run_db(_gather)

    def _csv(rows: list[dict], fields: list[str]) -> str:
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)
        return buf.getvalue()

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    manifest = (
        f"{title}\n"
        f"Generated: {generated}\n"
        f"Scope: {len(asset_ids)} assets\n\n"
        "Contents:\n"
        "  controls.csv        — SOC 2 controls with effective status, attestation, evidence\n"
        "  mapped_findings.csv — open findings substantiating each control's status\n"
        "  accepted_risks.csv  — dismissed findings and the rationale for accepting them\n"
    )

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("MANIFEST.txt", manifest)
        zf.writestr("controls.csv", _csv(data["controls"], [
            "control_id", "title", "category", "status", "manual_status",
            "evidence_note", "assessed_by", "assessed_at", "open_findings",
        ]))
        zf.writestr("mapped_findings.csv", _csv(data["mapped"], [
            "control_id", "tool", "severity", "state", "identity_key", "rationale",
        ]))
        zf.writestr("accepted_risks.csv", _csv(data["accepted"], [
            "severity", "title", "source", "reason", "decided_by", "age_days",
        ]))
    return out.getvalue()


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
    elif report_type == "executive":
        # The executive summary is a narrative board-level PDF; CSV/JSON would
        # strip the framing that makes it useful, so only PDF is offered.
        if fmt != "pdf":
            raise ValueError("executive reports only support pdf format")
        content = _serialize_executive_pdf(asset_ids=asset_ids, title=effective_title)
        content_type = "application/pdf"
        row_count = 1
    elif report_type == "risk_register":
        if fmt == "pdf":
            content = _serialize_risk_register_pdf(asset_ids=asset_ids, title=effective_title)
            content_type = "application/pdf"
        elif fmt == "csv":
            content = _serialize_risk_register_csv(asset_ids=asset_ids)
            content_type = "text/csv"
        else:
            raise ValueError("risk register reports support pdf or csv format")
        row_count = 1
    elif report_type == "soc2_evidence":
        if fmt != "zip":
            raise ValueError("soc2 evidence reports only support zip format")
        content = _serialize_soc2_evidence_zip(asset_ids=asset_ids, title=effective_title)
        content_type = "application/zip"
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
    """Report visibility: creator always sees it; others only if EVERY asset the
    report spans is within the viewer's accessible asset_ids.

    A rendered report's bytes aggregate findings across all of the creator's
    asset_ids, so containment (not mere intersection) is the correct scope — a
    viewer entitled to only one of the spanned assets must not download an
    artifact that also contains findings for assets they lack a grant to.
    A report without persisted asset_ids (legacy rows) falls back to creator-only.
    """
    if report.created_by == viewer_id:
        return True
    persisted = (report.filters or {}).get("asset_ids")
    if not persisted:
        return False
    return set(persisted).issubset(viewer_asset_ids)


def list_reports(
    viewer_id: str,
    viewer_asset_ids: list[str],
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Report], int]:
    """List reports visible to the viewer.

    The grant-intersection check runs in Python after fetching a window
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
