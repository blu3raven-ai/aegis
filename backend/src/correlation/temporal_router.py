"""Read API for Phase 11 temporal correlation metrics.

All endpoints return JSON suitable for dashboard charts and no auth is
added here — the global JWT middleware in main.py covers every route.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Query

from src.correlation.temporal import TemporalAggregator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/temporal", tags=["temporal"])

_aggregator = TemporalAggregator()


@router.get("/series")
def get_time_series(
    metric: str,
    org_id: str,
    bucket_size: str = "1d",
    since_days: int = Query(default=30, ge=1, le=365),
    scanner_type: str | None = None,
    severity: str | None = None,
):
    """Return a time-series for dashboard charts.

    Returns one data point per bucket that matches the requested filters.
    """
    since = datetime.now(timezone.utc) - timedelta(days=since_days)

    dim_filter: dict[str, str] | None = None
    if scanner_type or severity:
        dim_filter = {}
        if scanner_type:
            dim_filter["scanner_type"] = scanner_type
        if severity:
            dim_filter["severity"] = severity

    points = _aggregator.query(
        org_id=org_id,
        metric_type=metric,
        dimension_filter=dim_filter,
        bucket_size=bucket_size,
        since=since,
    )

    return {
        "metric": metric,
        "org_id": org_id,
        "bucket_size": bucket_size,
        "since_days": since_days,
        "series": [
            {
                "bucket_start": p.bucket.start.isoformat(),
                "value": p.value,
                "dimension": p.dimension,
            }
            for p in points
        ],
    }


@router.get("/top-authors")
def get_top_authors(
    org_id: str,
    since_days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=100),
):
    """Return the top N authors by findings introduced, with severity breakdown."""
    since = datetime.now(timezone.utc) - timedelta(days=since_days)

    points = _aggregator.query(
        org_id=org_id,
        metric_type="findings_introduced",
        bucket_size="1d",
        since=since,
        limit=10_000,
    )

    # Aggregate per author with per-severity breakdown.
    author_totals: dict[str, float] = {}
    author_breakdown: dict[str, dict[str, float]] = {}
    for p in points:
        author = p.dimension.get("author", "unknown")
        sev = p.dimension.get("severity", "unknown")
        author_totals[author] = author_totals.get(author, 0.0) + p.value
        author_breakdown.setdefault(author, {})
        author_breakdown[author][sev] = author_breakdown[author].get(sev, 0.0) + p.value

    sorted_authors = sorted(author_totals.items(), key=lambda kv: kv[1], reverse=True)[:limit]

    return {
        "org_id": org_id,
        "since_days": since_days,
        "authors": [
            {
                "author": author,
                "total": total,
                "breakdown": author_breakdown.get(author, {}),
            }
            for author, total in sorted_authors
        ],
    }


@router.get("/mttr")
def get_mttr(
    org_id: str,
    since_days: int = Query(default=30, ge=1, le=365),
    group_by: str = Query(default="scanner_type", pattern="^(scanner_type|severity)$"),
):
    """Return MTTR distribution grouped by scanner_type or severity.

    Values are in milliseconds; callers convert to desired units.
    """
    since = datetime.now(timezone.utc) - timedelta(days=since_days)

    points = _aggregator.query(
        org_id=org_id,
        metric_type="mttr",
        bucket_size="1d",
        since=since,
        limit=10_000,
    )

    # Compute average MTTR per group key.
    group_sum: dict[str, float] = {}
    group_count: dict[str, int] = {}
    for p in points:
        key = p.dimension.get(group_by, "unknown")
        group_sum[key] = group_sum.get(key, 0.0) + p.value
        group_count[key] = group_count.get(key, 0) + 1

    return {
        "org_id": org_id,
        "since_days": since_days,
        "group_by": group_by,
        "mttr": [
            {
                group_by: key,
                "avg_ms": group_sum[key] / group_count[key],
                "sample_count": group_count[key],
            }
            for key in sorted(group_sum)
        ],
    }
