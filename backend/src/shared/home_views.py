"""Read helpers for home dashboard, scoped by asset_ids.

The home-dashboard materialised views were dropped in Plan D's cleanup
migration. These helpers query the findings table directly instead, joined
to the assets table for display names.
"""
from __future__ import annotations

import logging

import sqlalchemy as sa

from src.db.helpers import run_db

logger = logging.getLogger(__name__)


def get_severity_counts_by_asset_ids(asset_ids: list[str], tool: str, state: str = "open") -> dict[str, int]:
    """Return {total, critical, high, medium, low} scoped to a list of asset UUIDs."""
    if not asset_ids:
        return {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

    async def _q(session):
        stmt = sa.text(
            """
            SELECT lower(severity) AS sev, count(*) AS n
            FROM findings
            WHERE asset_id = ANY(:asset_ids) AND tool = :tool AND state = :state
            GROUP BY lower(severity)
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids, "tool": tool, "state": state})).fetchall()
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in rows:
            if row.sev in counts:
                counts[row.sev] = int(row.n)
        counts["total"] = sum(counts.values())
        return counts

    return run_db(_q)


def get_top_repositories_by_asset_ids(asset_ids: list[str], limit: int = 5) -> list[dict]:
    """Return top-N repos by open/critical/high counts, scoped to asset UUIDs.

    Groups open findings by asset_id and joins the assets table for
    display_name. Sort order: critical desc, high desc, total open desc.
    """
    if not asset_ids:
        return []

    async def _q(session):
        stmt = sa.text(
            """
            SELECT
                a.id AS asset_id,
                a.display_name AS name,
                count(*) FILTER (WHERE lower(f.severity) = 'critical') AS critical,
                count(*) FILTER (WHERE lower(f.severity) = 'high')     AS high,
                count(*) AS open
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.asset_id = ANY(:asset_ids) AND f.state = 'open'
            GROUP BY a.id, a.display_name
            ORDER BY critical DESC, high DESC, open DESC
            LIMIT :limit
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids, "limit": limit})).fetchall()
        # Shape matches HomeRepoSummary in graphql/types.py — keep keys in
        # lockstep with that strawberry type or splat construction will raise.
        return [
            {
                "name": row.name,
                "critical": int(row.critical or 0),
                "high": int(row.high or 0),
                "open": int(row.open or 0),
            }
            for row in rows
        ]

    return run_db(_q)


def get_age_buckets_by_asset_ids(asset_ids: list[str]) -> dict[str, int]:
    """Return {label: count} for the 4 age buckets, scoped to asset UUIDs."""
    default = {"< 7 days": 0, "7-30 days": 0, "30-90 days": 0, "> 90 days": 0}
    if not asset_ids:
        return default

    async def _q(session):
        stmt = sa.text(
            """
            SELECT
                CASE
                    WHEN age_days < 7   THEN '< 7 days'
                    WHEN age_days < 30  THEN '7-30 days'
                    WHEN age_days < 90  THEN '30-90 days'
                    ELSE                     '> 90 days'
                END AS age_bucket,
                count(*) AS n
            FROM (
                SELECT EXTRACT(EPOCH FROM (now() - created_at)) / 86400 AS age_days
                FROM findings
                WHERE asset_id = ANY(:asset_ids) AND state = 'open'
            ) sub
            GROUP BY age_bucket
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchall()
        out = dict(default)
        for row in rows:
            if row.age_bucket in out:
                out[row.age_bucket] = int(row.n)
        return out

    return run_db(_q)


def get_remediation_stats_by_asset_ids(asset_ids: list[str]) -> dict:
    """Return {total_fixed, avg_days, median_days, fixed_last_30d}, scoped to asset UUIDs."""
    default = {"total_fixed": 0, "avg_days": None, "median_days": None, "fixed_last_30d": 0}
    if not asset_ids:
        return default

    async def _q(session):
        stmt = sa.text(
            """
            SELECT
                count(*)                                                                AS total_fixed,
                avg(EXTRACT(EPOCH FROM (fixed_at - created_at)) / 86400)               AS avg_days,
                percentile_cont(0.5) WITHIN GROUP (
                    ORDER BY EXTRACT(EPOCH FROM (fixed_at - created_at)) / 86400
                )                                                                       AS median_days,
                count(*) FILTER (WHERE fixed_at >= now() - INTERVAL '30 days')         AS fixed_last_30d
            FROM findings
            WHERE asset_id = ANY(:asset_ids)
              AND state = 'fixed'
              AND fixed_at IS NOT NULL
              AND created_at IS NOT NULL
            """
        )
        row = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchone()
        if not row or row.total_fixed == 0:
            return dict(default)
        return {
            "total_fixed": int(row.total_fixed),
            "avg_days": round(float(row.avg_days), 1) if row.avg_days is not None else None,
            "median_days": round(float(row.median_days), 1) if row.median_days is not None else None,
            "fixed_last_30d": int(row.fixed_last_30d or 0),
        }

    return run_db(_q)


def refresh_all_home_views() -> None:
    """No-op after the home-dashboard MVs were dropped in Plan D's cleanup migration.

    Retained as a stub so the startup wiring in main.py and the
    home_views_refresher worker don't break. Remove in a follow-up that also
    drops the worker if it's no longer producing value.
    """
    return
