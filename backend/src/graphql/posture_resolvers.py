"""Posture resolvers — trend + home analytics."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, and_

from src.db.helpers import run_db
from src.db.models import ScanRun
from src.graphql.types import HomeAnalytics, HomeRepoSummary, HomeAgeBucket, HomeRemediationStats, PostureTrendPoint
from src.shared.archived_filter import exclude_archived
from src.shared.home_views import get_top_repositories_by_asset_ids, get_age_buckets_by_asset_ids, get_remediation_stats_by_asset_ids


TOOLS = ("dependencies", "code_scanning", "container_scanning", "secrets")


def posture_trend(*, days: int = 30, info_context: dict) -> list[PostureTrendPoint]:
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, min(days, 90)))

    def _query(session):
        stmt = (
            select(ScanRun)
            .where(
                and_(
                    ScanRun.tool.in_(TOOLS),
                    ScanRun.asset_id.in_(asset_ids),
                    ScanRun.status == "completed",
                    ScanRun.finished_at >= cutoff,
                )
            )
            .order_by(ScanRun.finished_at.asc())
        )
        # Posture trend is a current-state view — archived scan runs must not
        # contribute to the historical chart.
        stmt = exclude_archived(stmt, ScanRun)
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
    asset_ids = info_context.get("asset_ids", [])
    if not asset_ids:
        return HomeAnalytics(
            top_repositories=[],
            age_buckets=[],
            remediation=HomeRemediationStats(
                total_fixed=0, avg_days=None, median_days=None, fixed_last_30d=0,
            ),
        )

    top_repos = get_top_repositories_by_asset_ids(asset_ids, limit=5)
    age_buckets = get_age_buckets_by_asset_ids(asset_ids)
    rem = get_remediation_stats_by_asset_ids(asset_ids)

    return HomeAnalytics(
        top_repositories=[HomeRepoSummary(**r) for r in top_repos],
        age_buckets=[HomeAgeBucket(label=k, count=v) for k, v in age_buckets.items()],
        remediation=HomeRemediationStats(
            total_fixed=rem["total_fixed"],
            avg_days=rem["avg_days"],
            median_days=rem["median_days"],
            fixed_last_30d=rem["fixed_last_30d"],
        ),
    )
