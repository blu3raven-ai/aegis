"""TemporalAggregator — bucketed time-series storage for Phase 11 Type 4 rules.

Provides record/query/rollup against the temporal_aggregates table.
Rules call record() on every relevant event; the read API calls query()
to feed the dashboard charts.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from sqlalchemy import select, update as sa_update, func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from src.db.helpers import run_db
from src.db.models import TemporalAggregate

logger = logging.getLogger(__name__)

# Supported bucket sizes and their timedelta equivalents.
_BUCKET_DELTAS: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
    "1w": timedelta(weeks=1),
}


def _floor_bucket(ts: datetime, bucket_size: str) -> datetime:
    """Truncate a timestamp to the start of its bucket."""
    if bucket_size == "1h":
        return ts.replace(minute=0, second=0, microsecond=0)
    if bucket_size == "1d":
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)
    if bucket_size == "1w":
        # ISO week starts on Monday.
        return (ts - timedelta(days=ts.weekday())).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    raise ValueError(f"unsupported bucket_size: {bucket_size!r}")


def _encode_dimension(dimension: dict[str, str]) -> str:
    """Stable, sorted encoding so callers don't need to order keys."""
    return "|".join(f"{k}={v}" for k, v in sorted(dimension.items()))


def _decode_dimension(dimension_key: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in dimension_key.split("|"):
        if "=" in part:
            k, _, v = part.partition("=")
            result[k] = v
    return result


@dataclass
class TimeBucket:
    start: datetime
    size: str  # "1h" | "1d" | "1w"


@dataclass
class TemporalDataPoint:
    bucket: TimeBucket
    value: float
    dimension: dict[str, str]


class TemporalAggregator:
    """Records and queries bucketed time-series aggregates.

    session_factory is a zero-arg callable returning a run_db-compatible
    coroutine — in production this is just the global run_db adapter; in
    tests a testcontainers session is injected.
    """

    def __init__(self, session_factory: Callable | None = None) -> None:
        # session_factory is unused in the default path (run_db uses the global
        # engine); it exists so tests can swap in an async session maker.
        self._session_factory = session_factory

    # ── write ─────────────────────────────────────────────────────────────────

    def record(
        self,
        *,
        org_id: str,
        metric_type: str,
        dimension: dict[str, str],
        value: float = 1.0,
        timestamp: datetime | None = None,
        bucket_size: str = "1d",
    ) -> None:
        """Upsert +value into the matching bucket.

        Uses Postgres ON CONFLICT DO UPDATE so concurrent writers converge
        without an explicit SELECT → UPDATE race.
        """
        if bucket_size not in _BUCKET_DELTAS:
            raise ValueError(f"unsupported bucket_size: {bucket_size!r}")

        ts = timestamp or datetime.now(timezone.utc)
        bucket_start = _floor_bucket(ts, bucket_size)
        dim_key = _encode_dimension(dimension)

        async def _upsert(session) -> None:
            stmt = (
                pg_insert(TemporalAggregate)
                .values(
                    org_id=org_id,
                    metric_type=metric_type,
                    dimension_key=dim_key,
                    bucket_start=bucket_start,
                    bucket_size=bucket_size,
                    value=value,
                )
                .on_conflict_do_update(
                    constraint="uq_temporal_aggregate_bucket",
                    set_={"value": TemporalAggregate.value + value},
                )
            )
            await session.execute(stmt)

        run_db(_upsert)

    # ── read ──────────────────────────────────────────────────────────────────

    def query(
        self,
        *,
        org_id: str,
        metric_type: str,
        dimension_filter: dict[str, str] | None = None,
        bucket_size: str = "1d",
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 1000,
    ) -> list[TemporalDataPoint]:
        """Return data points matching the given filters, newest-first."""
        async def _fetch(session) -> list[TemporalAggregate]:
            q = (
                select(TemporalAggregate)
                .where(
                    TemporalAggregate.org_id == org_id,
                    TemporalAggregate.metric_type == metric_type,
                    TemporalAggregate.bucket_size == bucket_size,
                )
                .order_by(TemporalAggregate.bucket_start.desc())
                .limit(limit)
            )
            if since is not None:
                q = q.where(TemporalAggregate.bucket_start >= since)
            if until is not None:
                q = q.where(TemporalAggregate.bucket_start <= until)
            result = await session.execute(q)
            return list(result.scalars().all())

        rows = run_db(_fetch)
        points: list[TemporalDataPoint] = []
        for row in rows:
            dim = _decode_dimension(row.dimension_key)
            # Apply post-fetch dimension filter — avoids building a dynamic SQL
            # LIKE predicate that could miss multi-value keys.
            if dimension_filter and not all(
                dim.get(k) == v for k, v in dimension_filter.items()
            ):
                continue
            points.append(
                TemporalDataPoint(
                    bucket=TimeBucket(start=row.bucket_start, size=row.bucket_size),
                    value=row.value,
                    dimension=dim,
                )
            )
        return points

    # ── rollup ────────────────────────────────────────────────────────────────

    def rollup(
        self,
        *,
        org_id: str,
        metric_type: str,
        from_bucket: str,
        to_bucket: str,
    ) -> int:
        """Aggregate fine-grained buckets into a coarser bucket.

        Returns the number of source rows consumed. Each unique
        (dimension_key, coarse_bucket_start) group is summed and upserted
        into the target bucket size. Source rows are NOT deleted — callers
        may retain them for audit or further rollup.
        """
        if from_bucket not in _BUCKET_DELTAS or to_bucket not in _BUCKET_DELTAS:
            raise ValueError(f"unsupported bucket sizes: {from_bucket!r} → {to_bucket!r}")

        async def _do_rollup(session) -> int:
            result = await session.execute(
                select(TemporalAggregate).where(
                    TemporalAggregate.org_id == org_id,
                    TemporalAggregate.metric_type == metric_type,
                    TemporalAggregate.bucket_size == from_bucket,
                )
            )
            rows = list(result.scalars().all())

            # Group by (dimension_key, coarse bucket start).
            groups: dict[tuple[str, datetime], float] = {}
            for row in rows:
                coarse_start = _floor_bucket(row.bucket_start, to_bucket)
                key = (row.dimension_key, coarse_start)
                groups[key] = groups.get(key, 0.0) + row.value

            for (dim_key, coarse_start), total in groups.items():
                stmt = (
                    pg_insert(TemporalAggregate)
                    .values(
                        org_id=org_id,
                        metric_type=metric_type,
                        dimension_key=dim_key,
                        bucket_start=coarse_start,
                        bucket_size=to_bucket,
                        value=total,
                    )
                    .on_conflict_do_update(
                        constraint="uq_temporal_aggregate_bucket",
                        set_={"value": TemporalAggregate.value + total},
                    )
                )
                await session.execute(stmt)

            return len(rows)

        return run_db(_do_rollup)
