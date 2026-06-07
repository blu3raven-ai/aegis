"""Posture snapshot service.

Aggregates org-scoped findings + repos and delegates to build_analytics() in
src.shared.analytics.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.helpers import run_db
from src.db.models import Asset, Finding, Repo
from src.shared.analytics import AnalyticsPayload, build_analytics
from src.shared.archived_filter import exclude_archived


def _finding_to_dict(f: Finding, asset: Asset | None = None) -> dict[str, Any]:
    return {
        "security_advisory": {"severity": f.severity},
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "fixed_at": f.fixed_at.isoformat() if f.fixed_at else None,
        "repository": {"full_name": (asset.display_name if asset is not None else "")},
    }


def _repo_to_dict(r: Repo, asset: Asset | None = None) -> dict[str, Any]:
    return {
        "id": r.id,
        "full_name": (asset.display_name if asset is not None else ""),
        "archived": False,
        "disabled": False,
    }


def get_posture_snapshot(
    org: str | None = None,
    *,
    asset_ids: list[str] | None = None,
) -> AnalyticsPayload:
    """Fetch findings + repos and return the analytics payload.

    Supply either ``org`` (legacy path) or ``asset_ids`` (asset-identity path).
    Passing ``asset_ids=[]`` returns an empty payload immediately.
    """
    if asset_ids is None and org is None:
        raise ValueError("either org or asset_ids is required")

    async def _query(session: AsyncSession) -> AnalyticsPayload:
        if asset_ids is not None and not asset_ids:
            return build_analytics(open_findings=[], fixed_findings=[], repos=[])

        if asset_ids is not None:
            finding_filter_open = Finding.asset_id.in_(asset_ids)
            finding_filter_fixed = Finding.asset_id.in_(asset_ids)
            repo_filter = Repo.asset_id.in_(asset_ids)
        else:
            raise ValueError(
                "get_posture_snapshot: org-only path not supported after Plan D; supply asset_ids"
            )

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
        repo_rows = (await session.execute(
            select(Repo, Asset)
            .join(Asset, Asset.id == Repo.asset_id)
            .where(repo_filter)
        )).all()

        open_dicts = [_finding_to_dict(f, a) for f, a in open_rows]
        fixed_dicts = [_finding_to_dict(f, a) for f, a in fixed_rows]
        repo_dicts = [_repo_to_dict(r, a) for r, a in repo_rows]

        return build_analytics(
            open_findings=open_dicts,
            fixed_findings=fixed_dicts,
            repos=repo_dicts,
        )

    return run_db(_query)


def upsert_posture_snapshot(org: str, payload: AnalyticsPayload) -> None:
    """Write today's posture snapshot for the org. Safe to call multiple times — upserts."""
    from dataclasses import asdict

    # Always midnight UTC so (org, snapshot_at) stays unique per day
    snap_at = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    payload_dict = asdict(payload)

    async def _upsert(session: AsyncSession) -> None:
        await session.execute(
            text("""
                INSERT INTO posture_snapshots (org, snapshot_at, payload)
                VALUES (:org, :snap_at, :payload::jsonb)
                ON CONFLICT (org, snapshot_at)
                DO UPDATE SET payload = EXCLUDED.payload
            """),
            {"org": org, "snap_at": snap_at, "payload": json.dumps(payload_dict)},
        )

    run_db(_upsert)


def get_posture_by_team(
    org: str | None = None,
    *,
    asset_ids: list[str] | None = None,
) -> list[dict]:
    """Return per-team posture snapshots keyed by TeamAsset memberships.

    Supply ``asset_ids`` (asset-identity path). The legacy ``org`` parameter is
    no longer supported after Plan D — pass asset_ids resolved from the org instead.
    Teams with no TeamAsset rows in scope are excluded.
    """
    if asset_ids is None:
        raise ValueError(
            "get_posture_by_team: org-only path not supported after Plan D; supply asset_ids"
        )

    from dataclasses import asdict

    from src.db.models import Team, TeamAsset

    async def _query(session: AsyncSession) -> list[dict]:
        teams = (await session.execute(select(Team))).scalars().all()
        if not teams:
            return []

        if not asset_ids:
            return []
        finding_filter_open = Finding.asset_id.in_(asset_ids)
        finding_filter_fixed = Finding.asset_id.in_(asset_ids)
        repo_filter = Repo.asset_id.in_(asset_ids)

        # Map team → asset_ids via TeamAsset (replaces legacy TeamRepository)
        team_asset_rows = (await session.execute(
            select(TeamAsset).where(TeamAsset.asset_id.in_(asset_ids))
        )).scalars().all()
        team_assets: dict[str, list[str]] = {}
        for ta in team_asset_rows:
            team_assets.setdefault(ta.team_id, []).append(ta.asset_id)

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
        all_repos = (await session.execute(
            select(Repo).where(repo_filter)
        )).scalars().all()

        in_scope_teams = [t for t in teams if t.id in team_assets]
        results = []
        for team in in_scope_teams:
            assets_in_team = set(team_assets[team.id])
            open_dicts = [_finding_to_dict(f) for f in all_open if f.asset_id in assets_in_team]
            fixed_dicts = [_finding_to_dict(f) for f in all_fixed if f.asset_id in assets_in_team]
            repo_dicts = [_repo_to_dict(r) for r in all_repos if r.asset_id in assets_in_team]

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


def get_posture_trend(
    org: str | None = None,
    days: int = 30,
    *,
    asset_ids: list[str] | None = None,
) -> list[dict]:
    """Return daily posture data points for the last ``days`` days.

    The trend table (posture_snapshots) is still keyed by org; when
    ``asset_ids`` is supplied we recompute the snapshot live from Finding rows
    rather than reading the pre-computed table, because the table has no
    asset-scoped rows yet.
    """
    if asset_ids is None and org is None:
        raise ValueError("either org or asset_ids is required")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    async def _query(session: AsyncSession) -> list[dict]:
        if asset_ids is not None:
            # asset_ids path: trend table is org-keyed; return empty until the
            # snapshot table gains asset-scoped rows (tracked separately).
            return []

        rows = (await session.execute(
            text("""
                SELECT snapshot_at, payload
                FROM posture_snapshots
                WHERE org = :org AND snapshot_at >= :cutoff
                ORDER BY snapshot_at ASC
            """),
            {"org": org, "cutoff": cutoff},
        )).all()
        return [
            {
                "date":       r.snapshot_at.strftime("%Y-%m-%d"),
                "risk_score": (r.payload.get("riskScore") or {}).get("score", 0),
                "critical":   (r.payload.get("counts") or {}).get("critical", 0),
                "high":       (r.payload.get("counts") or {}).get("high", 0),
                "medium":     (r.payload.get("counts") or {}).get("medium", 0),
                "low":        (r.payload.get("counts") or {}).get("low", 0),
                "total":      (r.payload.get("counts") or {}).get("total", 0),
            }
            for r in rows
        ]

    return run_db(_query)
