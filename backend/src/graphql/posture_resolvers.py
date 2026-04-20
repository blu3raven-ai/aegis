"""Posture resolvers — trend + home analytics."""
from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, and_, func

from src.db.helpers import run_db
from src.db.models import Finding, ScanRun
from src.graphql.types import HomeAnalytics, HomeRepoSummary, HomeAgeBucket, HomeRemediationStats, PostureTrendPoint


TOOLS = ("dependencies", "code_scanning", "container_scanning", "secrets")


def posture_trend(*, days: int = 30, info_context: dict) -> list[PostureTrendPoint]:
    orgs = info_context.get("orgs", [])
    if not orgs:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 90)))

    def _query(session):
        stmt = (
            select(ScanRun)
            .where(
                and_(
                    ScanRun.tool.in_(TOOLS),
                    ScanRun.org.in_(orgs),
                    ScanRun.status == "completed",
                    ScanRun.finished_at >= cutoff,
                )
            )
            .order_by(ScanRun.finished_at.asc())
        )
        return session.execute(stmt).scalars().all()

    runs = run_db(lambda s: _query(s))

    daily: dict[str, dict[str, dict]] = defaultdict(dict)

    for run in runs:
        if not run.finished_at:
            continue
        day = run.finished_at.strftime("%Y-%m-%d")
        meta = run.metadata_json or {}
        counts = meta.get("counts", {})
        daily[day][run.tool] = {
            "total": counts.get("total", 0),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
        }

    last_known: dict[str, dict] = {}
    points: list[PostureTrendPoint] = []
    start = cutoff.date()
    end = datetime.now(timezone.utc).date()
    current = start

    while current <= end:
        day_str = current.strftime("%Y-%m-%d")
        if day_str in daily:
            for tool, counts in daily[day_str].items():
                last_known[tool] = counts

        total = critical = high = medium = low = 0
        for tool_counts in last_known.values():
            total += tool_counts.get("total", 0)
            critical += tool_counts.get("critical", 0)
            high += tool_counts.get("high", 0)
            medium += tool_counts.get("medium", 0)
            low += tool_counts.get("low", 0)

        points.append(PostureTrendPoint(
            date=day_str,
            total=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low,
        ))
        current += timedelta(days=1)

    return points


def home_analytics(*, info_context: dict) -> HomeAnalytics:
    orgs = info_context.get("orgs", [])
    if not orgs:
        return HomeAnalytics(
            top_repositories=[], age_buckets=[], remediation=HomeRemediationStats(total_fixed=0, avg_days=None, median_days=None, fixed_last_30d=0),
        )

    now = datetime.now(timezone.utc)

    def _query(session):
        stmt = select(Finding).where(and_(Finding.org.in_(orgs), Finding.state == "open"))
        return session.execute(stmt).scalars().all()

    def _fixed_query(session):
        cutoff = now - timedelta(days=365)
        stmt = select(Finding).where(and_(Finding.org.in_(orgs), Finding.state == "fixed", Finding.fixed_at >= cutoff))
        return session.execute(stmt).scalars().all()

    open_findings = run_db(lambda s: _query(s))
    fixed_findings = run_db(lambda s: _fixed_query(s))

    repo_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"open": 0, "critical": 0, "high": 0})
    age_counts = {"< 7 days": 0, "7-30 days": 0, "30-90 days": 0, "> 90 days": 0}

    for f in open_findings:
        repo = f.repository or "unknown"
        sev = (f.severity or "").lower()
        repo_counts[repo]["open"] += 1
        if sev == "critical":
            repo_counts[repo]["critical"] += 1
        elif sev == "high":
            repo_counts[repo]["high"] += 1

        age_days = (now - f.first_seen_at).days if f.first_seen_at else 0
        if age_days < 7:
            age_counts["< 7 days"] += 1
        elif age_days < 30:
            age_counts["7-30 days"] += 1
        elif age_days < 90:
            age_counts["30-90 days"] += 1
        else:
            age_counts["> 90 days"] += 1

    top_repos = sorted(repo_counts.items(), key=lambda x: (-x[1]["critical"], -x[1]["high"], -x[1]["open"]))[:5]

    fix_durations: list[float] = []
    fixed_last_30d = 0
    for f in fixed_findings:
        if f.fixed_at and f.first_seen_at:
            days = max(0.0, (f.fixed_at - f.first_seen_at).total_seconds() / 86400)
            fix_durations.append(days)
        if f.fixed_at and (now - f.fixed_at).days <= 30:
            fixed_last_30d += 1

    return HomeAnalytics(
        top_repositories=[HomeRepoSummary(name=name, open=c["open"], critical=c["critical"], high=c["high"]) for name, c in top_repos],
        age_buckets=[HomeAgeBucket(label=label, count=count) for label, count in age_counts.items()],
        remediation=HomeRemediationStats(
            total_fixed=len(fixed_findings),
            avg_days=round(statistics.mean(fix_durations), 1) if fix_durations else None,
            median_days=round(statistics.median(fix_durations), 1) if fix_durations else None,
            fixed_last_30d=fixed_last_30d,
        ),
    )
