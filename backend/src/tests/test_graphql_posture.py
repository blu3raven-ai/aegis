"""Unit tests for the posture GraphQL resolvers.

Covers postureSnapshot, postureByTeam, and postureTrend — verifying scope
propagation, empty-scope fail-closed behaviour, shape correctness, and the
day-window clamping on trend.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.graphql.schema import PostureQuery
from src.shared.analytics import (
    AgeBucket, AnalyticsPayload, Counts, RemediationMetrics, RepositoryCoverage,
    RiskScore, SeverityDistributionItem, TopRepository,
)


def _info():
    return SimpleNamespace(context={"request": SimpleNamespace()})


def _payload(critical: int = 0, high: int = 0) -> AnalyticsPayload:
    return AnalyticsPayload(
        counts=Counts(total=critical + high, critical=critical, high=high, medium=0, low=0),
        severityDistribution=[
            SeverityDistributionItem(severity="critical", count=critical, percentage=50),
            SeverityDistributionItem(severity="high", count=high, percentage=50),
        ],
        ageBuckets=[AgeBucket(label="0-7d", count=critical + high)],
        topRepositories=[
            TopRepository(name="acme/api", open=critical + high, critical=critical, high=high),
        ],
        remediation=RemediationMetrics(
            totalFixed=3, avgDays=2.5, medianDays=2.0, fixedLast30d=1,
        ),
        repositoryCoverage=RepositoryCoverage(total=10, affected=4, unaffected=6, percentage=40),
        riskScore=RiskScore(score=72, rating="High", summary="Critical work needed"),
    )


@pytest.fixture
def empty_scope_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": [],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


@pytest.fixture
def scoped_ctx():
    with patch(
        "src.graphql.auth.get_graphql_context",
        new=AsyncMock(return_value={
            "user_id": "u", "role": "viewer", "asset_ids": ["asset-1", "asset-2"],
            "tier": "community", "request": object(), "_cache": {},
        }),
    ):
        yield


# ── postureSnapshot ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_posture_snapshot_empty_scope_returns_zero_payload(empty_scope_ctx):
    """Empty scope must not leak data — service handles it and returns an
    empty analytics payload built from no findings."""
    empty = _payload(critical=0, high=0)
    with patch(
        "src.posture.resolvers.get_posture_snapshot",
        return_value=empty,
    ) as svc:
        result = await PostureQuery().snapshot(_info())

    assert svc.call_args.kwargs["asset_ids"] == []
    assert result.counts.total == 0
    assert result.risk_score.rating == "High"  # fixture value, not data-driven


@pytest.mark.asyncio
async def test_posture_snapshot_returns_shape(scoped_ctx):
    payload = _payload(critical=2, high=4)
    with patch(
        "src.posture.resolvers.get_posture_snapshot",
        return_value=payload,
    ) as svc:
        result = await PostureQuery().snapshot(_info())

    assert svc.call_args.kwargs["asset_ids"] == ["asset-1", "asset-2"]
    assert result.counts.critical == 2
    assert result.counts.high == 4
    assert result.counts.total == 6
    # Camel→snake mapping for nested remediation block
    assert result.remediation.total_fixed == 3
    assert result.remediation.fixed_last_30d == 1
    assert result.repository_coverage.percentage == 40
    assert result.risk_score.score == 72
    assert len(result.severity_distribution) == 2


# ── postureByTeam ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_posture_by_team_empty_scope_returns_empty(empty_scope_ctx):
    with patch(
        "src.posture.resolvers.get_posture_by_team",
        return_value=[],
    ) as svc:
        result = await PostureQuery().by_team(_info())

    assert svc.call_args.kwargs["asset_ids"] == []
    assert result == []


@pytest.mark.asyncio
async def test_posture_by_team_returns_rows(scoped_ctx):
    rows = [
        {
            "team_id": "t1",
            "team_name": "platform",
            "repo_count": 3,
            "counts": {"total": 5, "critical": 2, "high": 1, "medium": 1, "low": 1},
            "risk_score": {"score": 80, "rating": "High", "summary": "needs attention"},
        },
    ]
    with patch(
        "src.posture.resolvers.get_posture_by_team",
        return_value=rows,
    ):
        result = await PostureQuery().by_team(_info())

    assert len(result) == 1
    assert result[0].team_id == "t1"
    assert result[0].team_name == "platform"
    assert result[0].repo_count == 3
    assert result[0].counts.critical == 2
    assert result[0].risk_score.score == 80


# ── postureTrend ───────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_posture_trend_empty_scope_returns_empty(empty_scope_ctx):
    with patch(
        "src.posture.resolvers.get_posture_trend",
        return_value=[],
    ) as svc:
        result = await PostureQuery().trend(_info(), days=30)

    assert result == []
    assert svc.call_args.kwargs["asset_ids"] == []


@pytest.mark.asyncio
async def test_posture_trend_returns_points_with_risk_score(scoped_ctx):
    rows = [
        {"date": "2026-06-15", "risk_score": 42, "critical": 1, "high": 2, "medium": 3, "low": 4, "total": 10},
        {"date": "2026-06-16", "risk_score": 38, "critical": 1, "high": 1, "medium": 2, "low": 4, "total": 8},
    ]
    with patch(
        "src.posture.resolvers.get_posture_trend",
        return_value=rows,
    ):
        result = await PostureQuery().trend(_info(), days=30)

    assert len(result) == 2
    assert result[0].date == "2026-06-15"
    assert result[0].risk_score == 42
    assert result[0].total == 10
    assert result[1].risk_score == 38


@pytest.mark.asyncio
async def test_posture_trend_clamps_days_to_safe_range(scoped_ctx):
    """Out-of-bounds day windows must be clamped before hitting the SQL layer.
    Mirrors the REST router's Query(ge=7, le=365) so callers can't burn the DB
    asking for a 10000-day window."""
    with patch(
        "src.posture.resolvers.get_posture_trend",
        return_value=[],
    ) as svc:
        await PostureQuery().trend(_info(), days=10000)
        await PostureQuery().trend(_info(), days=1)

    assert svc.call_args_list[0].kwargs["days"] == 365
    assert svc.call_args_list[1].kwargs["days"] == 7
