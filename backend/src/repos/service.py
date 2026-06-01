"""Repos asset management service — Phase 27.

Aggregates repo scan state from the `repos` table, scan_runs, findings, and
chains into RepoSummary / RepoDetail objects consumed by the REST endpoints.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any

from sqlalchemy import select, func, and_, case, distinct
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Repo, ScanRun, Finding, Chain, ChainEdge

# Scanners considered for coverage tracking — matches tool column values in scan_runs.
_SCANNER_TYPES = ("dependencies", "code_scanning", "container_scanning", "secrets")

# A scan run older than this is "stale" rather than "fresh".
_FRESH_WINDOW_DAYS = 7


@dataclass
class RepoSummary:
    repo_id: str                        # "org/repo"
    org: str
    repo: str
    last_scanned_sha: str | None
    manifest_set_hash: str | None
    last_scanned_at: datetime | None
    findings_count_by_severity: dict[str, int]
    chains_count: int
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
    repo: str | None
    first_seen_at: str
    last_seen_at: str


@dataclass
class ChainRow:
    id: str
    chain_type: str
    severity: str
    status: str
    created_at: str


@dataclass
class RepoDetail(RepoSummary):
    scan_history: list[ScanRunRow] = field(default_factory=list)
    active_findings: list[FindingRow] = field(default_factory=list)
    attached_chains: list[ChainRow] = field(default_factory=list)
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
    org_id: str | None,
    since_days: int | None,
    has_critical: bool | None,
    limit: int,
) -> list[RepoSummary]:
    """Core async aggregation query — runs in the db helper thread."""
    # Fetch all repos, optionally filtered by org.
    stmt = select(Repo)
    if org_id:
        stmt = stmt.where(Repo.org == org_id)
    stmt = stmt.order_by(Repo.updated_at.desc()).limit(limit)
    result = await session.execute(stmt)
    repos = result.scalars().all()

    if not repos:
        return []

    # Build a map from (org, repo) to last scan_run per tool.
    repo_keys = [(r.org, r.repo) for r in repos]

    # Subquery: most-recent finished_at per (org, tool, repo-derived).
    # scan_runs doesn't store repo directly — we join via findings where possible,
    # but for coverage we rely on the run belonging to the org and the tool type.
    # We get all completed scan runs per org within the window, then match.
    since_cutoff: datetime | None = None
    if since_days:
        since_cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)

    orgs = list({r.org for r in repos})

    scan_runs_stmt = (
        select(ScanRun.tool, ScanRun.org, func.max(ScanRun.finished_at).label("last_finished"))
        .where(ScanRun.org.in_(orgs))
        .where(ScanRun.status == "completed")
        .group_by(ScanRun.tool, ScanRun.org)
    )
    scan_runs_result = await session.execute(scan_runs_stmt)
    # Map: org -> tool -> last_finished
    scan_run_map: dict[str, dict[str, datetime]] = {}
    for tool, org, last_finished in scan_runs_result.all():
        scan_run_map.setdefault(org, {})[tool] = last_finished

    # Findings severity counts per (org, repo) — open findings only.
    finding_counts_stmt = (
        select(
            Finding.org,
            Finding.repo,
            Finding.severity,
            func.count(Finding.id).label("cnt"),
        )
        .where(Finding.org.in_(orgs))
        .where(Finding.state == "open")
        .group_by(Finding.org, Finding.repo, Finding.severity)
    )
    finding_result = await session.execute(finding_counts_stmt)
    # Map: (org, repo) -> severity -> count
    finding_map: dict[tuple[str, str], dict[str, int]] = {}
    for org, repo, severity, cnt in finding_result.all():
        key = (org, repo or "")
        finding_map.setdefault(key, {})[severity or "unknown"] = cnt

    # Chain counts per org — chains attach to org; we approximate per-repo
    # by looking at chain edges that reference findings for that repo.
    chains_stmt = (
        select(
            Finding.org,
            Finding.repo,
            func.count(distinct(ChainEdge.chain_id)).label("chain_cnt"),
        )
        .join(ChainEdge, ChainEdge.source_finding_id == Finding.id)
        .join(Chain, Chain.id == ChainEdge.chain_id)
        .where(Finding.org.in_(orgs))
        .where(Chain.status == "open")
        .group_by(Finding.org, Finding.repo)
    )
    chains_result = await session.execute(chains_stmt)
    chain_map: dict[tuple[str, str], int] = {}
    for org, repo, cnt in chains_result.all():
        chain_map[(org, repo or "")] = cnt

    summaries: list[RepoSummary] = []
    for r in repos:
        repo_tool_map = scan_run_map.get(r.org, {})
        scanners_with_coverage = [
            t for t in _SCANNER_TYPES if t in repo_tool_map
        ]

        # Most recent completed scan timestamp across all scanners for this org.
        tool_timestamps = list(repo_tool_map.values())
        last_scanned_at = max(tool_timestamps) if tool_timestamps else None

        sev_raw = finding_map.get((r.org, r.repo), {})
        findings_count_by_severity = {
            "critical": sev_raw.get("critical", 0),
            "high": sev_raw.get("high", 0),
            "medium": sev_raw.get("medium", 0),
            "low": sev_raw.get("low", 0),
        }

        # Apply has_critical filter post-aggregation.
        if has_critical is True and findings_count_by_severity["critical"] == 0:
            continue

        chains_count = chain_map.get((r.org, r.repo), 0)
        repo_id = f"{r.org}/{r.repo}"

        # Apply since_days filter: skip repos with no scan or scan older than window.
        if since_cutoff and (last_scanned_at is None or last_scanned_at < since_cutoff):
            continue

        summaries.append(RepoSummary(
            repo_id=repo_id,
            org=r.org,
            repo=r.repo,
            last_scanned_sha=_truncate(r.last_scanned_sha, 7),
            manifest_set_hash=_truncate(r.manifest_set_hash, 8),
            last_scanned_at=last_scanned_at,
            findings_count_by_severity=findings_count_by_severity,
            chains_count=chains_count,
            scanners_with_coverage=scanners_with_coverage,
            coverage_status=_coverage_status(last_scanned_at),
        ))

    return summaries


async def _get_repo_async(
    session: AsyncSession,
    org: str,
    repo_name: str,
) -> RepoDetail | None:
    result = await session.execute(
        select(Repo).where(and_(Repo.org == org, Repo.repo == repo_name))
    )
    r = result.scalar_one_or_none()
    if r is None:
        return None

    # Scan history: last 10 completed runs across all scanner types.
    scan_history_result = await session.execute(
        select(ScanRun)
        .where(ScanRun.org == org)
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

    # Active findings for this repo.
    findings_result = await session.execute(
        select(Finding)
        .where(and_(Finding.org == org, Finding.repo == repo_name, Finding.state == "open"))
        .order_by(Finding.first_seen_at.desc())
        .limit(50)
    )
    findings = findings_result.scalars().all()

    active_findings: list[FindingRow] = [
        FindingRow(
            id=f.id,
            tool=f.tool,
            severity=f.severity,
            state=f.state,
            identity_key=f.identity_key,
            repo=f.repo,
            first_seen_at=f.first_seen_at.isoformat(),
            last_seen_at=f.last_seen_at.isoformat(),
        )
        for f in findings
    ]

    # Chains attached via findings edges.
    chains_result = await session.execute(
        select(Chain)
        .join(ChainEdge, Chain.id == ChainEdge.chain_id)
        .join(Finding, Finding.id == ChainEdge.source_finding_id)
        .where(and_(Finding.org == org, Finding.repo == repo_name))
        .where(Chain.status == "open")
        .distinct()
        .limit(20)
    )
    chains = chains_result.scalars().all()

    attached_chains: list[ChainRow] = [
        ChainRow(
            id=c.id,
            chain_type=c.chain_type,
            severity=c.severity,
            status=c.status,
            created_at=c.created_at.isoformat(),
        )
        for c in chains
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
        select(Finding.severity, func.count(Finding.id))
        .where(and_(Finding.org == org, Finding.repo == repo_name, Finding.state == "open"))
        .group_by(Finding.severity)
    )
    sev_raw = {row[0] or "unknown": row[1] for row in sev_result.all()}
    findings_count_by_severity = {
        "critical": sev_raw.get("critical", 0),
        "high": sev_raw.get("high", 0),
        "medium": sev_raw.get("medium", 0),
        "low": sev_raw.get("low", 0),
    }

    chains_count_result = await session.execute(
        select(func.count(distinct(ChainEdge.chain_id)))
        .join(Finding, Finding.id == ChainEdge.source_finding_id)
        .join(Chain, Chain.id == ChainEdge.chain_id)
        .where(and_(Finding.org == org, Finding.repo == repo_name, Chain.status == "open"))
    )
    chains_count = chains_count_result.scalar() or 0

    return RepoDetail(
        repo_id=f"{org}/{repo_name}",
        org=org,
        repo=repo_name,
        last_scanned_sha=_truncate(r.last_scanned_sha, 7),
        manifest_set_hash=_truncate(r.manifest_set_hash, 8),
        last_scanned_at=last_scanned_at,
        findings_count_by_severity=findings_count_by_severity,
        chains_count=chains_count,
        scanners_with_coverage=scanner_tools,
        coverage_status=_coverage_status(last_scanned_at),
        scan_history=scan_history,
        active_findings=active_findings,
        attached_chains=attached_chains,
    )


class RepoService:
    """Public API for repos asset management queries."""

    @staticmethod
    def list_repos(
        org_id: str | None = None,
        since_days: int | None = None,
        has_critical: bool | None = None,
        limit: int = 100,
    ) -> list[RepoSummary]:
        async def _run(session: AsyncSession) -> list[RepoSummary]:
            return await _list_repos_async(session, org_id, since_days, has_critical, min(limit, 500))

        return run_db(_run)

    @staticmethod
    def get_repo(org: str, repo_name: str) -> RepoDetail | None:
        async def _run(session: AsyncSession) -> RepoDetail | None:
            return await _get_repo_async(session, org, repo_name)

        return run_db(_run)
