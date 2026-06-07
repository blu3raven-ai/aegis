"""Pydantic response models for /api/v1/posture/snapshot.

Mirrors the AnalyticsPayload dataclass in src.shared.analytics. Field names
match the source dataclasses exactly so the router can pass asdict(payload)
into the response model unchanged.
"""
from __future__ import annotations

from pydantic import BaseModel


class CountsModel(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int


class SeverityDistributionItemModel(BaseModel):
    severity: str
    count: int
    percentage: int


class AgeBucketModel(BaseModel):
    label: str
    count: int


class TopRepositoryModel(BaseModel):
    name: str
    open: int
    critical: int
    high: int


class RemediationMetricsModel(BaseModel):
    totalFixed: int
    avgDays: float | None = None
    medianDays: float | None = None
    fixedLast30d: int


class RepositoryCoverageModel(BaseModel):
    total: int
    affected: int
    unaffected: int
    percentage: int


class RiskScoreModel(BaseModel):
    score: int
    rating: str
    summary: str


class PostureSnapshotResponse(BaseModel):
    counts: CountsModel
    severityDistribution: list[SeverityDistributionItemModel]
    ageBuckets: list[AgeBucketModel]
    topRepositories: list[TopRepositoryModel]
    remediation: RemediationMetricsModel
    repositoryCoverage: RepositoryCoverageModel
    riskScore: RiskScoreModel


class TrendPoint(BaseModel):
    date: str
    risk_score: int
    critical: int
    high: int
    medium: int
    low: int
    total: int


class PostureTrendResponse(BaseModel):
    points: list[TrendPoint]
    days: int


class TeamPostureItem(BaseModel):
    team_id: str
    team_name: str
    repo_count: int
    counts: CountsModel
    risk_score: RiskScoreModel


class PostureByTeamResponse(BaseModel):
    teams: list[TeamPostureItem]
    org: str
