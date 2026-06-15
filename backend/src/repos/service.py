"""Repos asset management service — Phase 27.

Aggregates repo scan state from the `assets` table, scan_runs, and findings
into RepoSummary / RepoDetail objects consumed by the REST endpoints.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, ScanRun, Finding
from src.shared.archived_filter import exclude_archived

# Scanners considered for coverage tracking — matches tool column values in scan_runs.
_SCANNER_TYPES = ("dependencies", "code_scanning", "container_scanning", "secrets")

# A scan run older than this is "stale" rather than "fresh".
_FRESH_WINDOW_DAYS = 7


@dataclass
class RepoSummary:
    asset_id: str
    display_name: str
    last_scanned_sha: str | None
    manifest_set_hash: str | None
    last_scanned_at: datetime | None
    findings_count_by_severity: dict[str, int]
    scanners_with_coverage: list[str]
    coverage_status: str                # 'fresh' | 'stale' | 'never'
    source_url: str | None = None


@dataclass
class ScanRunRow:
    scan_id: str
    scanner_type: str
    status: str
    started_at: str
    duration_ms: int | None
    findings_count: int


@dataclass
class FindingRow:
    id: int
    tool: str
    severity: str | None
    state: str
    identity_key: str
    asset_id: str | None
    first_seen_at: str
    last_seen_at: str


@dataclass
class RepoDetail(RepoSummary):
    scan_history: list[ScanRunRow] = field(default_factory=list)
    active_findings: list[FindingRow] = field(default_factory=list)
    default_branch: str | None = None


def _coverage_status(last_scanned_at: datetime | None) -> str:
    if last_scanned_at is None:
        return "never"
    cutoff = datetime.now(timezone.utc) - timedelta(days=_FRESH_WINDOW_DAYS)
    return "fresh" if last_scanned_at >= cutoff else "stale"


def _truncate(value: str | None, length: int) -> str | None:
    if value is None:
        return None
    return value[:length]


async def _list_repos_async(
    session: AsyncSession,
    asset_ids: list[str],
    since_days: int | None,
    has_critical: bool | None,
    limit: int,
) -> list[RepoSummary]:
    """Core async aggregation query — runs in the db helper thread."""
    if not asset_ids:
        return []

    # Fetch assets scoped to the provided asset_ids — scan state lives on Asset.
    stmt = (
        select(Asset)
        .where(Asset.id.in_(asset_ids))
        .order_by(Asset.updated_at.desc())
        .limit(limit)
    )
    result = await session.execute(stmt)
    assets = result.scalars().all()

    if not assets:
        return []

    repo_asset_ids = [a.id for a in assets]

    since_cutoff: datetime | None = None
    if since_days:
        since_cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    # Most-recent finished_at per (asset_id, tool) from completed scan runs.
    scan_runs_stmt = (
        select(ScanRun.tool, ScanRun.asset_id, func.max(ScanRun.finished_at).label("last_finished"))
        .where(ScanRun.asset_id.in_(repo_asset_ids))
        .where(ScanRun.status == "completed")
        .group_by(ScanRun.tool, ScanRun.asset_id)
    )
    scan_runs_result = await session.execute(scan_runs_stmt)
    # Map: asset_id -> tool -> last_finished
    scan_run_map: dict[str, dict[str, datetime]] = {}
    for tool, asset_id, last_finished in scan_runs_result.all():
        scan_run_map.setdefault(asset_id, {})[tool] = last_finished

    # Findings severity counts per asset_id — open findings only.
    finding_counts_stmt = (
        select(
            Finding.asset_id,
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(Finding.asset_id.in_(repo_asset_ids))
        .where(Finding.state == "open")
        .group_by(Finding.asset_id, Finding.severity)
    )
    finding_counts_stmt = exclude_archived(finding_counts_stmt, Finding)
    finding_result = await session.execute(finding_counts_stmt)
    # Map: asset_id -> severity -> count
    finding_map: dict[str, dict[str, int]] = {}
    for asset_id, severity, cnt in finding_result.all():
        finding_map.setdefault(asset_id, {})[severity or "unknown"] = cnt

    summaries: list[RepoSummary] = []
    for a in assets:
        repo_tool_map = scan_run_map.get(a.id, {})
        scanners_with_coverage = [
            t for t in _SCANNER_TYPES if t in repo_tool_map
        ]

        # Most recent completed scan timestamp across all scanners for this asset.
        tool_timestamps = list(repo_tool_map.values())
        last_scanned_at = max(tool_timestamps) if tool_timestamps else None

        sev_raw = finding_map.get(a.id, {})
        findings_count_by_severity = {
            "critical": sev_raw.get("critical", 0),
            "high": sev_raw.get("high", 0),
            "medium": sev_raw.get("medium", 0),
            "low": sev_raw.get("low", 0),
        }

        # Apply has_critical filter post-aggregation.
        if has_critical is True and findings_count_by_severity["critical"] == 0:
            continue

        # Apply since_days filter: skip repos with no scan or scan older than window.
        if since_cutoff and (last_scanned_at is None or last_scanned_at < since_cutoff):
            continue

        summaries.append(RepoSummary(
            asset_id=a.id,
            display_name=a.display_name,
            last_scanned_sha=_truncate(a.last_scanned_sha, 7),
            manifest_set_hash=_truncate(a.manifest_set_hash, 8),
            last_scanned_at=last_scanned_at,
            findings_count_by_severity=findings_count_by_severity,
            scanners_with_coverage=scanners_with_coverage,
            coverage_status=_coverage_status(last_scanned_at),
        ))

    return summaries


async def _get_repo_async(
    session: AsyncSession,
    asset_id: str,
    asset_ids: list[str],
) -> RepoDetail | None:
    # Fail-closed: scope to the viewer's accessible asset_ids. An empty list
    # (no team membership) yields no matches, returning 404 at the router.
    if not asset_ids or asset_id not in asset_ids:
        return None
    asset = (await session.execute(
        select(Asset).where(Asset.id == asset_id)
    )).scalar_one_or_none()
    if asset is None:
        return None

    # Scan history: last 10 completed runs across all scanner types for this asset.
    scan_history_result = await session.execute(
        select(ScanRun)
        .where(ScanRun.asset_id == asset_id)
        .order_by(ScanRun.started_at.desc().nullslast())
        .limit(10)
    )
    scan_runs = scan_history_result.scalars().all()

    scan_history: list[ScanRunRow] = []
    for run in scan_runs:
        duration_ms: int | None = None
        if run.started_at and run.finished_at:
            delta = run.finished_at - run.started_at
            duration_ms = int(delta.total_seconds() * 1000)

        # findings_count from metadata_json if available, else 0.
        fc = 0
        if run.metadata_json:
            fc = run.metadata_json.get("findings_count", 0)

        scan_history.append(ScanRunRow(
            scan_id=run.id,
            scanner_type=run.tool,
            status=run.status,
            started_at=run.started_at.isoformat() if run.started_at else "",
            duration_ms=duration_ms,
            findings_count=fc,
        ))

    # Active findings for this asset.
    findings_result = await session.execute(
        exclude_archived(
            select(Finding)
            .where(and_(Finding.asset_id == asset_id, Finding.state == "open"))
            .order_by(Finding.first_seen_at.desc())
            .limit(50),
            Finding,
        )
    )
    findings = findings_result.scalars().all()

    active_findings: list[FindingRow] = [
        FindingRow(
            id=f.id,
            tool=f.tool,
            severity=f.severity,
            state=f.state,
            identity_key=f.identity_key,
            asset_id=f.asset_id,
            first_seen_at=f.first_seen_at.isoformat(),
            last_seen_at=f.last_seen_at.isoformat(),
        )
        for f in findings
    ]

    # Per-tool scan map for coverage.
    tool_timestamps: list[datetime] = []
    scanner_tools: list[str] = []
    for run in scan_runs:
        if run.status == "completed" and run.finished_at:
            tool_timestamps.append(run.finished_at)
            if run.tool not in scanner_tools:
                scanner_tools.append(run.tool)

    last_scanned_at = max(tool_timestamps) if tool_timestamps else None

    sev_result = await session.execute(
        exclude_archived(
            select(Finding.severity, func.count(Finding.id))
            .where(and_(Finding.asset_id == asset_id, Finding.state == "open"))
            .group_by(Finding.severity),
            Finding,
        )
    )
    sev_raw = {row[0] or "unknown": row[1] for row in sev_result.all()}
    findings_count_by_severity = {
        "critical": sev_raw.get("critical", 0),
        "high": sev_raw.get("high", 0),
        "medium": sev_raw.get("medium", 0),
        "low": sev_raw.get("low", 0),
    }

    return RepoDetail(
        asset_id=asset.id,
        display_name=asset.display_name,
        last_scanned_sha=_truncate(asset.last_scanned_sha, 7),
        manifest_set_hash=_truncate(asset.manifest_set_hash, 8),
        last_scanned_at=last_scanned_at,
        findings_count_by_severity=findings_count_by_severity,
        scanners_with_coverage=scanner_tools,
        coverage_status=_coverage_status(last_scanned_at),
        scan_history=scan_history,
        active_findings=active_findings,
    )


class RepoService:
    """Public API for repos asset management queries."""

    @staticmethod
    def list_repos(
        asset_ids: list[str],
        since_days: int | None = None,
        has_critical: bool | None = None,
        limit: int = 100,
    ) -> list[RepoSummary]:
        async def _run(session: AsyncSession) -> list[RepoSummary]:
            return await _list_repos_async(session, asset_ids, since_days, has_critical, min(limit, 500))

        return run_db(_run)

    @staticmethod
    def get_repo(asset_id: str, asset_ids: list[str]) -> RepoDetail | None:
        async def _run(session: AsyncSession) -> RepoDetail | None:
            return await _get_repo_async(session, asset_id, asset_ids)

        return run_db(_run)
