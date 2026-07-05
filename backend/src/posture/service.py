"""Posture snapshot service.

Aggregates asset-scoped findings + repos and delegates to build_analytics()
in src.shared.analytics.
"""
from __future__ import annotations

from datetime import date as _date
from datetime import datetime, timedelta, timezone
from typing import Any

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, Finding, KevEntry, Team
from src.shared.analytics import (
    AnalyticsPayload, SEVERITY_WEIGHTS, build_analytics, finding_exposure_weight,
    posture_risk_gauge_from_raw, posture_weighted_volume,
)
from src.shared.archived_filter import exclude_archived


def _finding_to_dict(
    f: Finding, asset: Asset | None = None, *, kev_listed: bool = False,
) -> dict[str, Any]:
    return {
        "security_advisory": {"severity": f.severity},
        # Exploitability signals for the risk gauge. reachability comes from the
        # finding detail JSONB (when a scanner/analysis wrote it); kev_listed is
        # resolved by the caller against the KEV mirror.
        "kev_listed": kev_listed,
        "reachability": (f.detail or {}).get("reachability"),
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

        # Resolve KEV membership for the open findings in one query (the risk
        # gauge weights KEV-listed findings higher). Fixed findings don't feed
        # the gauge, so they don't need it.
        open_cves = {f.cve_id for f, _ in open_rows if f.cve_id}
        kev_set: set[str] = set()
        if open_cves:
            kev_set = set((await session.execute(
                select(KevEntry.cve_id).where(KevEntry.cve_id.in_(open_cves))
            )).scalars().all())

        open_dicts = [_finding_to_dict(f, a, kev_listed=f.cve_id in kev_set) for f, a in open_rows]
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
        from sqlalchemy import Date, cast

        sev = func.lower(Finding.severity)
        rows = (await session.execute(
            select(
                Finding.asset_id,
                func.coalesce(func.sum(case((sev == "critical", 1), else_=0)), 0).label("critical"),
                func.coalesce(func.sum(case((sev == "high", 1), else_=0)), 0).label("high"),
                func.coalesce(func.sum(case((sev == "medium", 1), else_=0)), 0).label("medium"),
                func.coalesce(func.sum(case((sev == "low", 1), else_=0)), 0).label("low"),
            )
            .where(
                Finding.state == "open",
                Finding.asset_id.isnot(None),
                Finding.archived.is_(False),
            )
            .group_by(Finding.asset_id)
        )).all()
        sev_by_asset = {r.asset_id: r for r in rows}

        # Count findings first seen (created) today, regardless of current state.
        # Uses created_at (UTC) cast to Date so the window is calendar-day aligned.
        new_rows = (await session.execute(
            select(
                Finding.asset_id,
                func.count(Finding.id).label("new_count"),
            )
            .where(
                cast(Finding.created_at, Date) == snapshot_date,
                Finding.asset_id.isnot(None),
                Finding.archived.is_(False),
            )
            .group_by(Finding.asset_id)
        )).all()
        new_by_asset: dict[str, int] = {r.asset_id: int(r.new_count) for r in new_rows}

        # Exploitability-weighted raw per asset (severity × action band). Fetched
        # at finding grain so the weighting reuses finding_exposure_weight — no
        # SQL band mirror to keep in sync. reachability from detail JSONB, KEV via
        # the mirror. Absence-neutral: with no signals this equals the severity
        # weighted volume, so risk_score is unchanged until enrichment lands.
        from collections import defaultdict

        is_kev_col = Finding.cve_id.in_(select(KevEntry.cve_id))
        weight_rows = (await session.execute(
            select(
                Finding.asset_id,
                Finding.severity,
                is_kev_col.label("is_kev"),
                Finding.detail["reachability"].astext.label("reachability"),
            ).where(
                Finding.state == "open",
                Finding.asset_id.isnot(None),
                Finding.archived.is_(False),
            )
        )).all()
        raw_by_asset: dict[str, float] = defaultdict(float)
        for wr in weight_rows:
            raw_by_asset[wr.asset_id] += finding_exposure_weight(
                wr.severity, kev_listed=bool(wr.is_kev), reachability=wr.reachability,
            )

        # Drive the upsert off every asset touched today: those with open
        # findings (rows) AND those whose only same-day activity was created and
        # already resolved/closed (present in new_by_asset/raw_by_asset but not
        # rows). Otherwise discovery velocity (new_findings) is silently lost for
        # discover-and-resolve days. Severity counts default to 0 for assets with
        # no open findings, preserving their open-finding semantics.
        all_asset_ids = set(sev_by_asset) | set(new_by_asset) | set(raw_by_asset)
        if not all_asset_ids:
            return 0

        values = []
        for asset_id in all_asset_ids:
            sev = sev_by_asset.get(asset_id)
            raw = raw_by_asset.get(asset_id, 0.0)
            values.append({
                "asset_id": asset_id,
                "snapshot_date": snapshot_date,
                "severity_critical": int(sev.critical) if sev else 0,
                "severity_high": int(sev.high) if sev else 0,
                "severity_medium": int(sev.medium) if sev else 0,
                "severity_low": int(sev.low) if sev else 0,
                # Band-weighted raw (pre-gauge) drives both the per-asset score
                # and the summed trend, so the hero and trend stay on one scale.
                "risk_weight": int(round(raw)),
                "risk_score": posture_risk_gauge_from_raw(raw),
                "new_findings": new_by_asset.get(asset_id, 0),
            })

        stmt = insert(PostureSnapshot).values(values)
        stmt = stmt.on_conflict_do_update(
            index_elements=["asset_id", "snapshot_date"],
            set_={
                "severity_critical": stmt.excluded.severity_critical,
                "severity_high": stmt.excluded.severity_high,
                "severity_medium": stmt.excluded.severity_medium,
                "severity_low": stmt.excluded.severity_low,
                "risk_score": stmt.excluded.risk_score,
                "risk_weight": stmt.excluded.risk_weight,
                "new_findings": stmt.excluded.new_findings,
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

        # Resolve KEV membership once for every in-scope open finding so the risk
        # gauge applies the KEV "act" weighting per team (mirrors
        # get_posture_snapshot). Fixed findings don't feed the gauge.
        open_cves = {f.cve_id for f in all_open if f.cve_id}
        kev_set: set[str] = set()
        if open_cves:
            kev_set = set((await session.execute(
                select(KevEntry.cve_id).where(KevEntry.cve_id.in_(open_cves))
            )).scalars().all())

        in_scope_teams = [t for t in teams if t.id in team_assets]
        results = []
        for team in in_scope_teams:
            assets_in_team = set(team_assets[team.id])
            open_dicts = [
                _finding_to_dict(f, kev_listed=f.cve_id in kev_set)
                for f in all_open if f.asset_id in assets_in_team
            ]
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
                func.sum(PostureSnapshot.risk_weight).label("risk_weight"),
                func.sum(PostureSnapshot.new_findings).label("new_findings"),
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
                "date":         r.snapshot_date.strftime("%Y-%m-%d"),
                # Gauge the SUM'd exploitability-weighted raw so the trend matches
                # the live hero (whose gauge is over org-wide weighted totals),
                # not an average of per-asset gauges. Backfilled rows carry the
                # severity weighted volume, so pre-enrichment history is unchanged.
                "risk_score":   posture_risk_gauge_from_raw(int(r.risk_weight or 0)),
                "critical":     critical,
                "high":         high,
                "medium":       medium,
                "low":          low,
                "total":        critical + high + medium + low,
                "new_findings": int(r.new_findings or 0),
            })
        return out

    return run_db(_query)


# ── Triage resolvers: scanner breakdown, risk contributions, exploitability, SLA
# Aggregations run as SQL GROUP BY over asset-scoped, open, non-archived findings
# (mirrors src/shared/home_views.py). Per-group risk is the raw additive
# weighted volume (posture_weighted_volume + SEVERITY_WEIGHTS) so contribution
# shares stay proportional — never re-derived inline, never clamped.


# Dimensions accepted by get_risk_contributions; everything else is BAD_INPUT at
# the resolver layer.
RISK_DIMENSIONS = ("scanner", "repo", "team", "severity", "ecosystem")


def get_scanner_breakdown(*, asset_ids: list[str]) -> list[dict[str, Any]]:
    """Open-finding severity counts per Finding.tool, with risk score and SLA breaches.

    Returns one dict per tool: {scanner, critical, high, medium, low, total,
    risk_score, sla_breached}. Fail-closed (empty list) on empty scope.
    """
    if not asset_ids:
        return []

    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        stmt = sa.text(
            """
            SELECT f.tool AS scanner,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'high') AS high,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'low') AS low,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE s.breached = true) AS sla_breached
            FROM findings f
            LEFT JOIN finding_sla_status s ON s.finding_id = f.id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
            GROUP BY f.tool
            """
        )
        rows = (
            await session.execute(stmt, {"asset_ids": asset_ids})
        ).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            critical = int(r.critical or 0)
            high = int(r.high or 0)
            medium = int(r.medium or 0)
            low = int(r.low or 0)
            out.append({
                "scanner": r.scanner,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "total": int(r.total or 0),
                "risk_score": posture_weighted_volume(
                    critical=critical, high=high, medium=medium, low=low,
                ),
                "sla_breached": int(r.sla_breached or 0),
            })
        # Sort by risk_score desc so the riskiest scanner leads, not the one
        # with the most (often low-severity) findings. The weighted volume is
        # already on each row, so this is a plain Python sort — the formula is
        # never re-derived inline (per the module note above). Scanner name asc
        # gives a deterministic tiebreak.
        out.sort(key=lambda r: (-r["risk_score"], r["scanner"]))
        return out

    return run_db(_query)


def get_risk_contributions(
    *, asset_ids: list[str], dimension: str
) -> list[dict[str, Any]]:
    """Per-group risk contribution across the requested dimension.

    Each row: {dimension, label, risk_score, count, percentage}. risk_score is
    the raw additive weighted volume for every dimension (``posture_weighted_volume``),
    so group scores sum to the org weighted total and ``percentage`` — the
    group's share of that total — is a true proportion (clamping the top group
    at 100 would understate its share). 0 on divide-by-zero. Fail-closed on
    empty scope.
    """
    if not asset_ids:
        return []

    if dimension == "severity":
        return _risk_by_severity(asset_ids)
    if dimension == "scanner":
        return _risk_by_tool(asset_ids)
    if dimension == "repo":
        return _risk_by_repo(asset_ids)
    if dimension == "team":
        return _risk_by_team(asset_ids)
    if dimension == "ecosystem":
        return _risk_by_ecosystem(asset_ids)
    # Caller validates against RISK_DIMENSIONS before reaching here.
    return []


def _risk_finish(rows: list[dict[str, Any]], *, dimension: str) -> list[dict[str, Any]]:
    """Attach percentage + sort by risk_score desc for a non-severity dimension."""
    total_org = sum(r["risk_score"] for r in rows)
    out: list[dict[str, Any]] = []
    for r in rows:
        pct = round(r["risk_score"] / total_org * 100) if total_org else 0
        out.append({
            "dimension": dimension,
            "label": r["label"],
            "risk_score": r["risk_score"],
            "count": r["count"],
            "percentage": pct,
        })
    out.sort(key=lambda x: x["risk_score"], reverse=True)
    return out


def _risk_by_tool(asset_ids: list[str]) -> list[dict[str, Any]]:
    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        stmt = sa.text(
            """
            SELECT f.tool AS label,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'high') AS high,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'low') AS low,
                   COUNT(*) AS total
            FROM findings f
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
            GROUP BY f.tool
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchall()
        raw: list[dict[str, Any]] = []
        for r in rows:
            c, h, m, l = int(r.critical or 0), int(r.high or 0), int(r.medium or 0), int(r.low or 0)
            raw.append({
                "label": r.label,
                "risk_score": posture_weighted_volume(critical=c, high=h, medium=m, low=l),
                "count": int(r.total or 0),
            })
        return _risk_finish(raw, dimension="scanner")

    return run_db(_query)


def _risk_by_repo(asset_ids: list[str]) -> list[dict[str, Any]]:
    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        stmt = sa.text(
            """
            SELECT a.display_name AS label,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'high') AS high,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'low') AS low,
                   COUNT(*) AS total
            FROM findings f
            JOIN assets a ON a.id = f.asset_id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
            GROUP BY a.display_name
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchall()
        raw: list[dict[str, Any]] = []
        for r in rows:
            c, h, m, l = int(r.critical or 0), int(r.high or 0), int(r.medium or 0), int(r.low or 0)
            raw.append({
                "label": r.label or "unknown",
                "risk_score": posture_weighted_volume(critical=c, high=h, medium=m, low=l),
                "count": int(r.total or 0),
            })
        return _risk_finish(raw, dimension="repo")

    return run_db(_query)


def _risk_by_team(asset_ids: list[str]) -> list[dict[str, Any]]:
    """Group by team membership via grants (subject_type='team').

    Mirrors get_posture_by_team's team->asset mapping: only teams granted an
    in-scope asset contribute. Fail-closed if no team grants cover the scope.
    """
    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        # Map team -> set of in-scope asset_ids.
        team_q = sa.text(
            """
            SELECT subject_id AS team_id, asset_id
            FROM grants
            WHERE subject_type = 'team' AND asset_id = ANY(:asset_ids)
            """
        )
        grant_rows = (await session.execute(team_q, {"asset_ids": asset_ids})).fetchall()
        if not grant_rows:
            return []
        team_assets: dict[str, list[str]] = {}
        for gr in grant_rows:
            team_assets.setdefault(gr.team_id, []).append(gr.asset_id)

        # Resolve team names in one pass (missing name -> team id).
        team_ids = list(team_assets.keys())
        name_q = select(Team.id, Team.name).where(Team.id.in_(team_ids))
        name_rows = (await session.execute(name_q)).all()
        names = {str(r.id): r.name or str(r.id) for r in name_rows}

        raw: list[dict[str, Any]] = []
        for team_id, aids in team_assets.items():
            stmt = sa.text(
                """
                SELECT
                  COUNT(*) FILTER (WHERE lower(severity) = 'critical') AS critical,
                  COUNT(*) FILTER (WHERE lower(severity) = 'high') AS high,
                  COUNT(*) FILTER (WHERE lower(severity) = 'medium') AS medium,
                  COUNT(*) FILTER (WHERE lower(severity) = 'low') AS low,
                  COUNT(*) AS total
                FROM findings
                WHERE asset_id = ANY(:asset_ids)
                  AND state = 'open'
                  AND archived = false
                """
            )
            r = (await session.execute(stmt, {"asset_ids": aids})).fetchone()
            if r is None:
                continue
            c, h, m, l = int(r.critical or 0), int(r.high or 0), int(r.medium or 0), int(r.low or 0)
            total = int(r.total or 0)
            if total == 0:
                continue
            raw.append({
                "label": names.get(team_id, team_id),
                "risk_score": posture_weighted_volume(critical=c, high=h, medium=m, low=l),
                "count": total,
            })
        return _risk_finish(raw, dimension="team")

    return run_db(_query)


def _risk_by_severity(asset_ids: list[str]) -> list[dict[str, Any]]:
    """One row per tier; risk_score is the raw weighted count so the four rows
    sum to the org weighted total — consistent with every other dimension's
    posture_weighted_volume (clamping would distort per-tier contribution)."""
    tiers = ("critical", "high", "medium", "low")

    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        stmt = sa.text(
            """
            SELECT lower(severity) AS sev, COUNT(*) AS n
            FROM findings
            WHERE asset_id = ANY(:asset_ids)
              AND state = 'open'
              AND archived = false
            GROUP BY lower(severity)
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchall()
        counts = {r.sev: int(r.n) for r in rows if r.sev}

        raw: list[dict[str, Any]] = []
        for tier in tiers:
            n = counts.get(tier, 0)
            raw.append({
                "label": tier,
                "risk_score": n * SEVERITY_WEIGHTS[tier],
                "count": n,
            })
        total_org = sum(r["risk_score"] for r in raw)
        out: list[dict[str, Any]] = []
        for r in raw:
            pct = round(r["risk_score"] / total_org * 100) if total_org else 0
            out.append({
                "dimension": "severity",
                "label": r["label"],
                "risk_score": r["risk_score"],
                "count": r["count"],
                "percentage": pct,
            })
        out.sort(key=lambda x: x["risk_score"], reverse=True)
        return out

    return run_db(_query)


def _risk_by_ecosystem(asset_ids: list[str]) -> list[dict[str, Any]]:
    """Group by SbomComponent.ecosystem joined via package_name.

    Mirrors sbom_ecosystem_analytics ecosystem resolution: findings with no
    component match fall into the unknown ("") ecosystem bucket.
    """
    async def _query(session: AsyncSession) -> list[dict[str, Any]]:
        # Collapse SbomComponent to one row per (asset_id, name) before joining:
        # the table's uniqueness is (asset_id, purl), so a bare join on name
        # would multiply a finding's counts by the number of versions — or
        # distinct ecosystems — a package resolves to in the SBOM. Mirrors
        # sbom_ecosystem_analytics.
        stmt = sa.text(
            """
            SELECT COALESCE(sc.ecosystem, '') AS label,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'critical') AS critical,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'high') AS high,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'medium') AS medium,
                   COUNT(*) FILTER (WHERE lower(f.severity) = 'low') AS low,
                   COUNT(*) AS total
            FROM findings f
            LEFT JOIN (
                SELECT DISTINCT ON (asset_id, name) asset_id, name, ecosystem
                FROM sbom_components
                WHERE asset_id = ANY(:asset_ids)
                ORDER BY asset_id, name, ecosystem
            ) sc ON sc.asset_id = f.asset_id AND sc.name = f.package_name
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
              AND f.package_name IS NOT NULL
            GROUP BY COALESCE(sc.ecosystem, '')
            """
        )
        rows = (await session.execute(stmt, {"asset_ids": asset_ids})).fetchall()
        raw: list[dict[str, Any]] = []
        for r in rows:
            c, h, m, l = int(r.critical or 0), int(r.high or 0), int(r.medium or 0), int(r.low or 0)
            total = int(r.total or 0)
            if total == 0:
                continue
            raw.append({
                "label": r.label or "",
                "risk_score": posture_weighted_volume(critical=c, high=h, medium=m, low=l),
                "count": total,
            })
        return _risk_finish(raw, dimension="ecosystem")

    return run_db(_query)


def get_exploitability_summary(*, asset_ids: list[str]) -> dict[str, Any]:
    """KEV + high-EPSS counts and the top EPSS-scored findings in scope.

    kev_count: open in-scope findings whose cve appears in kev_entries.
    high_epss_count: open in-scope findings joined to epss_scores with
    percentile >= 0.9. epss_top is delegated to EpssService (limit=10).
    Fail-closed on empty scope.
    """
    if not asset_ids:
        return {"kev_count": 0, "high_epss_count": 0, "epss_top": []}

    async def _query(session: AsyncSession) -> dict[str, Any]:
        kev_stmt = sa.text(
            """
            SELECT COUNT(*) AS n
            FROM findings f
            JOIN kev_entries k ON k.cve_id = f.cve_id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
            """
        )
        kev_count = int(
            (await session.execute(kev_stmt, {"asset_ids": asset_ids})).scalar() or 0
        )

        epss_stmt = sa.text(
            """
            SELECT COUNT(*) AS n
            FROM findings f
            JOIN epss_scores e ON e.cve = f.cve_id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
              AND e.percentile >= 0.9
            """
        )
        high_epss_count = int(
            (await session.execute(epss_stmt, {"asset_ids": asset_ids})).scalar() or 0
        )

        return {"kev_count": kev_count, "high_epss_count": high_epss_count}

    summary = run_db(_query)

    from src.epss.service import EpssService
    summary["epss_top"] = EpssService().top_findings_by_asset_ids(asset_ids, limit=10)
    return summary


def get_sla_posture(*, asset_ids: list[str]) -> dict[str, Any]:
    """SLA breach posture for open in-scope findings.

    total_breached = sum of per-severity breach counts; max_breach_age_days is
    the max breach_age_days over breached findings in scope (0 when none).
    by_scanner is breached count per Finding.tool, sorted desc. Fail-closed on
    empty scope.
    """
    if not asset_ids:
        return {
            "total_breached": 0,
            "critical_breached": 0,
            "high_breached": 0,
            "medium_breached": 0,
            "low_breached": 0,
            "max_breach_age_days": 0,
            "by_scanner": [],
        }

    async def _query(session: AsyncSession) -> dict[str, Any]:
        sev_stmt = sa.text(
            """
            SELECT lower(f.severity) AS sev, COUNT(*) AS n
            FROM findings f
            JOIN finding_sla_status s ON s.finding_id = f.id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
              AND s.breached = true
            GROUP BY lower(f.severity)
            """
        )
        sev_rows = (
            await session.execute(sev_stmt, {"asset_ids": asset_ids})
        ).fetchall()
        breaches = {r.sev: int(r.n) for r in sev_rows if r.sev}

        age_stmt = sa.text(
            """
            SELECT COALESCE(MAX(s.breach_age_days), 0) AS max_age
            FROM findings f
            JOIN finding_sla_status s ON s.finding_id = f.id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
              AND s.breached = true
            """
        )
        max_age = int(
            (await session.execute(age_stmt, {"asset_ids": asset_ids})).scalar() or 0
        )

        scanner_stmt = sa.text(
            """
            SELECT f.tool AS scanner, COUNT(*) AS breached
            FROM findings f
            JOIN finding_sla_status s ON s.finding_id = f.id
            WHERE f.asset_id = ANY(:asset_ids)
              AND f.state = 'open'
              AND f.archived = false
              AND s.breached = true
            GROUP BY f.tool
            ORDER BY COUNT(*) DESC
            """
        )
        scanner_rows = (
            await session.execute(scanner_stmt, {"asset_ids": asset_ids})
        ).fetchall()
        by_scanner = [
            {"scanner": r.scanner, "breached": int(r.breached or 0)}
            for r in scanner_rows
        ]

        total = sum(breaches.values())
        return {
            "total_breached": total,
            "critical_breached": breaches.get("critical", 0),
            "high_breached": breaches.get("high", 0),
            "medium_breached": breaches.get("medium", 0),
            "low_breached": breaches.get("low", 0),
            "max_breach_age_days": max_age,
            "by_scanner": by_scanner,
        }

    return run_db(_query)
