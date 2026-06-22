"""Posture snapshot service.

Aggregates asset-scoped findings + repos and delegates to build_analytics()
in src.shared.analytics.
"""
from __future__ import annotations

from datetime import date as _date
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, Finding
from src.shared.analytics import AnalyticsPayload, build_analytics
from src.shared.archived_filter import exclude_archived


def _finding_to_dict(f: Finding, asset: Asset | None = None) -> dict[str, Any]:
    return {
        "security_advisory": {"severity": f.severity},
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "fixed_at": f.fixed_at.isoformat() if f.fixed_at else None,
        "repository": {"full_name": (asset.display_name if asset is not None else "")},
    }


def _asset_to_repo_dict(asset: Asset) -> dict[str, Any]:
    return {
        "id": asset.id,
        "full_name": asset.display_name or "",
        "archived": bool(asset.archived),
        "disabled": False,
    }


def get_posture_snapshot(*, asset_ids: list[str]) -> AnalyticsPayload:
    """Fetch findings + repos and return the analytics payload.

    Passing ``asset_ids=[]`` returns an empty payload immediately.
    """
    async def _query(session: AsyncSession) -> AnalyticsPayload:
        if not asset_ids:
            return build_analytics(open_findings=[], fixed_findings=[], repos=[])

        finding_filter_open = Finding.asset_id.in_(asset_ids)
        finding_filter_fixed = Finding.asset_id.in_(asset_ids)
        asset_filter = Asset.id.in_(asset_ids)

        open_rows = (await session.execute(
            exclude_archived(
                select(Finding, Asset)
                .join(Asset, Asset.id == Finding.asset_id)
                .where(finding_filter_open, Finding.state == "open"),
                Finding,
            )
        )).all()
        fixed_rows = (await session.execute(
            exclude_archived(
                select(Finding, Asset)
                .join(Asset, Asset.id == Finding.asset_id)
                .where(finding_filter_fixed, Finding.state == "fixed"),
                Finding,
            )
        )).all()
        asset_rows = (await session.execute(
            select(Asset).where(asset_filter)
        )).scalars().all()

        open_dicts = [_finding_to_dict(f, a) for f, a in open_rows]
        fixed_dicts = [_finding_to_dict(f, a) for f, a in fixed_rows]
        repo_dicts = [_asset_to_repo_dict(a) for a in asset_rows]

        return build_analytics(
            open_findings=open_dicts,
            fixed_findings=fixed_dicts,
            repos=repo_dicts,
        )

    return run_db(_query)


def compute_and_store_daily_snapshots(*, today: _date | None = None) -> int:
    """Aggregate open findings per asset for ``today`` and upsert one row per asset.

    Returns the number of asset rows written. Called daily by the scheduler at
    midnight UTC; idempotent — calling twice on the same date replaces the row.
    """
    from sqlalchemy import case, func
    from sqlalchemy.dialects.postgresql import insert

    from src.db.models import PostureSnapshot

    snapshot_date = today or datetime.now(timezone.utc).date()

    async def _run(session: AsyncSession) -> int:
        sev = func.lower(Finding.severity)
        rows = (await session.execute(
            select(
                Finding.asset_id,
                func.coalesce(func.sum(case((sev == "critical", 1), else_=0)), 0).label("critical"),
                func.coalesce(func.sum(case((sev == "high", 1), else_=0)), 0).label("high"),
                func.coalesce(func.sum(case((sev == "medium", 1), else_=0)), 0).label("medium"),
                func.coalesce(func.sum(case((sev == "low", 1), else_=0)), 0).label("low"),
            )
            .where(Finding.state == "open", Finding.asset_id.isnot(None))
            .group_by(Finding.asset_id)
        )).all()

        if not rows:
            return 0

        # Simple 0-100 ordering for the trend chart; the full Counts->RiskScore
        # pipeline lives in src.shared.analytics for live dashboard reads.
        def _risk(c: int, h: int, m: int, lo: int) -> int:
            return min(100, c * 10 + h * 5 + m * 2 + lo)

        values = [
            {
                "asset_id": r.asset_id,
                "snapshot_date": snapshot_date,
                "severity_critical": int(r.critical),
                "severity_high": int(r.high),
                "severity_medium": int(r.medium),
                "severity_low": int(r.low),
                "risk_score": _risk(int(r.critical), int(r.high), int(r.medium), int(r.low)),
            }
            for r in rows
        ]

        stmt = insert(PostureSnapshot).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["asset_id", "snapshot_date"],
            set_={
                "severity_critical": stmt.excluded.severity_critical,
                "severity_high": stmt.excluded.severity_high,
                "severity_medium": stmt.excluded.severity_medium,
                "severity_low": stmt.excluded.severity_low,
                "risk_score": stmt.excluded.risk_score,
            },
        )
        await session.execute(stmt)
        return len(values)

    return run_db(_run)


def get_posture_by_team(*, asset_ids: list[str]) -> list[dict]:
    """Return per-team posture snapshots keyed by team grants.

    Teams with no grants in scope are excluded.
    """
    from dataclasses import asdict

    from src.db.models import Grant, Team

    async def _query(session: AsyncSession) -> list[dict]:
        if not asset_ids:
            return []

        teams = (await session.execute(select(Team))).scalars().all()
        if not teams:
            return []

        finding_filter_open = Finding.asset_id.in_(asset_ids)
        finding_filter_fixed = Finding.asset_id.in_(asset_ids)
        asset_filter = Asset.id.in_(asset_ids)

        # Map team → asset_ids via unified grants table
        team_asset_rows = (await session.execute(
            select(Grant).where(
                Grant.subject_type == "team",
                Grant.asset_id.in_(asset_ids),
            )
        )).scalars().all()
        team_assets: dict[str, list[str]] = {}
        for ta in team_asset_rows:
            team_assets.setdefault(ta.subject_id, []).append(ta.asset_id)

        all_open = (await session.execute(
            exclude_archived(
                select(Finding).where(finding_filter_open, Finding.state == "open"),
                Finding,
            )
        )).scalars().all()
        all_fixed = (await session.execute(
            exclude_archived(
                select(Finding).where(finding_filter_fixed, Finding.state == "fixed"),
                Finding,
            )
        )).scalars().all()
        all_assets = (await session.execute(
            select(Asset).where(asset_filter)
        )).scalars().all()

        in_scope_teams = [t for t in teams if t.id in team_assets]
        results = []
        for team in in_scope_teams:
            assets_in_team = set(team_assets[team.id])
            open_dicts = [_finding_to_dict(f) for f in all_open if f.asset_id in assets_in_team]
            fixed_dicts = [_finding_to_dict(f) for f in all_fixed if f.asset_id in assets_in_team]
            repo_dicts = [_asset_to_repo_dict(a) for a in all_assets if a.id in assets_in_team]

            payload = build_analytics(
                open_findings=open_dicts,
                fixed_findings=fixed_dicts,
                repos=repo_dicts,
            )
            p = asdict(payload)
            results.append({
                "team_id":    team.id,
                "team_name":  team.name,
                "repo_count": len(assets_in_team),
                "counts":     p["counts"],
                "risk_score": p["riskScore"],
            })

        results.sort(key=lambda t: t["risk_score"]["score"], reverse=True)
        return results

    return run_db(_query)


def get_posture_trend(*, asset_ids: list[str], days: int = 30) -> list[dict]:
    """Return daily severity totals for the caller's accessible assets.

    Aggregates posture_snapshots rows WHERE asset_id IN asset_ids
    GROUP BY snapshot_date. Empty asset_ids -> empty result.
    """
    from sqlalchemy import func

    from src.db.models import PostureSnapshot

    if not asset_ids:
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).date()

    async def _query(session: AsyncSession) -> list[dict]:
        rows = (await session.execute(
            select(
                PostureSnapshot.snapshot_date,
                func.sum(PostureSnapshot.severity_critical).label("critical"),
                func.sum(PostureSnapshot.severity_high).label("high"),
                func.sum(PostureSnapshot.severity_medium).label("medium"),
                func.sum(PostureSnapshot.severity_low).label("low"),
                func.avg(PostureSnapshot.risk_score).label("risk_score"),
            )
            .where(
                PostureSnapshot.asset_id.in_(asset_ids),
                PostureSnapshot.snapshot_date >= cutoff,
            )
            .group_by(PostureSnapshot.snapshot_date)
            .order_by(PostureSnapshot.snapshot_date.asc())
        )).all()

        out: list[dict] = []
        for r in rows:
            critical = int(r.critical or 0)
            high = int(r.high or 0)
            medium = int(r.medium or 0)
            low = int(r.low or 0)
            out.append({
                "date":       r.snapshot_date.strftime("%Y-%m-%d"),
                "risk_score": int(round(r.risk_score)) if r.risk_score is not None else 0,
                "critical":   critical,
                "high":       high,
                "medium":     medium,
                "low":        low,
                "total":      critical + high + medium + low,
            })
        return out

    return run_db(_query)
