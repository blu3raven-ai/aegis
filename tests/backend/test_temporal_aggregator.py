"""Tests for TemporalAggregator — record/query/rollup round-trips.

Uses the session-level testcontainers Postgres from conftest.py. Tables are
created by the _create_tables fixture; the TemporalAggregate model is
included in Base.metadata so no extra setup is needed.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from src.correlation.temporal import TemporalAggregator, TimeBucket, TemporalDataPoint
from src.db.helpers import run_db
from src.db.models import TemporalAggregate
from sqlalchemy import delete

ORG = "acme-org"


@pytest.fixture(autouse=True)
def _clean_temporal():
    """Delete all rows before each test to prevent cross-test pollution."""
    async def _del(session):
        await session.execute(delete(TemporalAggregate).where(TemporalAggregate.org_id == ORG))
    run_db(_del)
    yield


@pytest.fixture
def agg() -> TemporalAggregator:
    return TemporalAggregator()


# ── record ────────────────────────────────────────────────────────────────────


def test_record_creates_row(agg):
    agg.record(org_id=ORG, metric_type="findings_introduced", dimension={"author": "dev@example.org"})

    points = agg.query(org_id=ORG, metric_type="findings_introduced")
    assert len(points) == 1
    assert points[0].value == 1.0
    assert points[0].dimension["author"] == "dev@example.org"


def test_record_increments_same_bucket(agg):
    ts = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    dim = {"scanner_type": "deps", "severity": "critical"}

    agg.record(org_id=ORG, metric_type="findings_introduced", dimension=dim, timestamp=ts)
    agg.record(org_id=ORG, metric_type="findings_introduced", dimension=dim, timestamp=ts)
    agg.record(org_id=ORG, metric_type="findings_introduced", dimension=dim, timestamp=ts)

    points = agg.query(org_id=ORG, metric_type="findings_introduced", dimension_filter=dim)
    assert len(points) == 1
    assert points[0].value == 3.0


def test_record_separate_days_create_separate_buckets(agg):
    dim = {"severity": "high"}
    day1 = datetime(2026, 1, 1, 9, tzinfo=timezone.utc)
    day2 = datetime(2026, 1, 2, 9, tzinfo=timezone.utc)

    agg.record(org_id=ORG, metric_type="m", dimension=dim, timestamp=day1)
    agg.record(org_id=ORG, metric_type="m", dimension=dim, timestamp=day2)

    points = agg.query(org_id=ORG, metric_type="m")
    assert len(points) == 2


def test_record_custom_value(agg):
    agg.record(org_id=ORG, metric_type="mttr", dimension={"scanner_type": "secrets"}, value=50_000.0)
    points = agg.query(org_id=ORG, metric_type="mttr")
    assert points[0].value == 50_000.0


def test_record_rejects_unsupported_bucket_size(agg):
    with pytest.raises(ValueError, match="unsupported bucket_size"):
        agg.record(org_id=ORG, metric_type="m", dimension={}, bucket_size="30m")


# ── query ─────────────────────────────────────────────────────────────────────


def test_query_dimension_filter(agg):
    agg.record(org_id=ORG, metric_type="sv", dimension={"severity": "critical"})
    agg.record(org_id=ORG, metric_type="sv", dimension={"severity": "high"})

    points = agg.query(org_id=ORG, metric_type="sv", dimension_filter={"severity": "critical"})
    assert len(points) == 1
    assert points[0].dimension["severity"] == "critical"


def test_query_since_filter(agg):
    old = datetime(2026, 1, 1, tzinfo=timezone.utc)
    recent = datetime(2026, 3, 1, tzinfo=timezone.utc)

    agg.record(org_id=ORG, metric_type="m", dimension={}, timestamp=old)
    agg.record(org_id=ORG, metric_type="m", dimension={}, timestamp=recent)

    since = datetime(2026, 2, 1, tzinfo=timezone.utc)
    points = agg.query(org_id=ORG, metric_type="m", since=since)
    assert all(p.bucket.start >= since for p in points)
    assert len(points) == 1


def test_query_bucket_size_filter(agg):
    ts = datetime(2026, 1, 15, 10, tzinfo=timezone.utc)
    agg.record(org_id=ORG, metric_type="m", dimension={}, bucket_size="1h", timestamp=ts)
    agg.record(org_id=ORG, metric_type="m", dimension={}, bucket_size="1d", timestamp=ts)

    hourly = agg.query(org_id=ORG, metric_type="m", bucket_size="1h")
    daily = agg.query(org_id=ORG, metric_type="m", bucket_size="1d")

    assert len(hourly) == 1
    assert hourly[0].bucket.size == "1h"
    assert len(daily) == 1
    assert daily[0].bucket.size == "1d"


def test_query_returns_empty_for_unknown_metric(agg):
    points = agg.query(org_id=ORG, metric_type="nonexistent_metric")
    assert points == []


# ── rollup ────────────────────────────────────────────────────────────────────


def test_rollup_aggregates_hourly_to_daily(agg):
    day = datetime(2026, 1, 20, tzinfo=timezone.utc)
    dim = {"severity": "medium"}

    for hour in range(8):
        ts = day.replace(hour=hour)
        agg.record(org_id=ORG, metric_type="sv", dimension=dim, bucket_size="1h", timestamp=ts)

    count = agg.rollup(org_id=ORG, metric_type="sv", from_bucket="1h", to_bucket="1d")
    assert count == 8

    daily = agg.query(org_id=ORG, metric_type="sv", bucket_size="1d", dimension_filter=dim)
    assert len(daily) == 1
    assert daily[0].value == 8.0


def test_rollup_returns_zero_when_nothing_to_roll(agg):
    count = agg.rollup(org_id=ORG, metric_type="empty_metric", from_bucket="1h", to_bucket="1d")
    assert count == 0


def test_rollup_rejects_unsupported_bucket(agg):
    with pytest.raises(ValueError):
        agg.rollup(org_id=ORG, metric_type="m", from_bucket="5m", to_bucket="1d")
