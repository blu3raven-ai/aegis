"""Tests for the temporal read API router.

Uses real testcontainers Postgres (session-level fixture from conftest)
and a lightweight FastAPI test client. JWT middleware is bypassed via
a per-request middleware shim.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.correlation.temporal import TemporalAggregator
from src.correlation.temporal_router import router as temporal_router
from src.db.helpers import run_db
from src.db.models import TemporalAggregate
from sqlalchemy import delete

ORG = "acme-org"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(temporal_router)

    @app.middleware("http")
    async def _inject_user(request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_role = "admin"
        return await call_next(request)

    return app


@pytest.fixture
def client() -> TestClient:
    return TestClient(_make_app())


@pytest.fixture
def agg() -> TemporalAggregator:
    return TemporalAggregator()


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(delete(TemporalAggregate).where(TemporalAggregate.org_id == ORG))
    run_db(_del)
    yield


# ── /temporal/series ──────────────────────────────────────────────────────────


def test_series_empty(client):
    resp = client.get("/api/v1/temporal/series", params={"metric": "severity_velocity", "org_id": ORG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["metric"] == "severity_velocity"
    assert body["org_id"] == ORG
    assert body["series"] == []


def test_series_returns_points(client, agg):
    now = datetime.now(timezone.utc)
    dim = {"scanner_type": "deps", "severity": "high"}
    for i in range(3):
        agg.record(org_id=ORG, metric_type="severity_velocity", dimension=dim,
                   timestamp=now - timedelta(days=i))

    resp = client.get(
        "/api/v1/temporal/series",
        params={"metric": "severity_velocity", "org_id": ORG, "since_days": 10},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["series"]) == 3
    # Every point must have required keys
    for point in body["series"]:
        assert "bucket_start" in point
        assert "value" in point
        assert "dimension" in point


def test_series_filter_by_scanner_type(client, agg):
    now = datetime.now(timezone.utc)
    agg.record(org_id=ORG, metric_type="sv", dimension={"scanner_type": "deps", "severity": "low"}, timestamp=now)
    agg.record(org_id=ORG, metric_type="sv", dimension={"scanner_type": "sast", "severity": "low"},
               timestamp=now - timedelta(days=1))

    resp = client.get(
        "/api/v1/temporal/series",
        params={"metric": "sv", "org_id": ORG, "scanner_type": "deps"},
    )
    assert resp.status_code == 200
    points = resp.json()["series"]
    assert all(p["dimension"]["scanner_type"] == "deps" for p in points)


def test_series_bucket_size_forwarded(client, agg):
    ts = datetime.now(timezone.utc)
    agg.record(org_id=ORG, metric_type="sv", dimension={}, bucket_size="1h", timestamp=ts)

    resp = client.get(
        "/api/v1/temporal/series",
        params={"metric": "sv", "org_id": ORG, "bucket_size": "1h"},
    )
    assert resp.status_code == 200
    assert len(resp.json()["series"]) >= 1


# ── /temporal/top-authors ──────────────────────────────────────────────────────


def test_top_authors_empty(client):
    resp = client.get("/api/v1/temporal/top-authors", params={"org_id": ORG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["authors"] == []


def test_top_authors_returns_sorted_list(client, agg):
    now = datetime.now(timezone.utc)
    for _ in range(10):
        agg.record(org_id=ORG, metric_type="findings_introduced",
                   dimension={"author": "alpha@example.org", "scanner_type": "deps", "severity": "critical"},
                   timestamp=now)
    for _ in range(5):
        agg.record(org_id=ORG, metric_type="findings_introduced",
                   dimension={"author": "beta@example.org", "scanner_type": "sast", "severity": "high"},
                   timestamp=now)

    resp = client.get("/api/v1/temporal/top-authors", params={"org_id": ORG, "limit": 5})
    assert resp.status_code == 200
    authors = resp.json()["authors"]
    assert len(authors) >= 2
    # First author must have the highest total
    assert authors[0]["author"] == "alpha@example.org"
    assert authors[0]["total"] >= authors[1]["total"]
    # Breakdown must be present
    assert "breakdown" in authors[0]


def test_top_authors_limit_respected(client, agg):
    now = datetime.now(timezone.utc)
    for i in range(15):
        agg.record(org_id=ORG, metric_type="findings_introduced",
                   dimension={"author": f"user{i}@example.org", "scanner_type": "deps", "severity": "medium"},
                   timestamp=now - timedelta(hours=i))

    resp = client.get("/api/v1/temporal/top-authors", params={"org_id": ORG, "limit": 3})
    assert resp.status_code == 200
    assert len(resp.json()["authors"]) <= 3


# ── /temporal/mttr ────────────────────────────────────────────────────────────


def test_mttr_empty(client):
    resp = client.get("/api/v1/temporal/mttr", params={"org_id": ORG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["mttr"] == []


def test_mttr_returns_averages(client, agg):
    now = datetime.now(timezone.utc)
    # Two records for same group → avg should equal mean
    agg.record(org_id=ORG, metric_type="mttr",
               dimension={"scanner_type": "secrets", "severity": "critical"},
               value=100_000.0, timestamp=now)
    agg.record(org_id=ORG, metric_type="mttr",
               dimension={"scanner_type": "secrets", "severity": "critical"},
               value=200_000.0, timestamp=now - timedelta(days=1))

    resp = client.get("/api/v1/temporal/mttr", params={"org_id": ORG, "group_by": "scanner_type"})
    assert resp.status_code == 200
    mttr = resp.json()["mttr"]
    assert len(mttr) == 1
    row = mttr[0]
    assert row["scanner_type"] == "secrets"
    assert row["avg_ms"] == pytest.approx(150_000.0, rel=0.01)
    assert row["sample_count"] == 2


def test_mttr_group_by_severity(client, agg):
    now = datetime.now(timezone.utc)
    agg.record(org_id=ORG, metric_type="mttr",
               dimension={"scanner_type": "deps", "severity": "high"},
               value=50_000.0, timestamp=now)
    agg.record(org_id=ORG, metric_type="mttr",
               dimension={"scanner_type": "sast", "severity": "low"},
               value=10_000.0, timestamp=now - timedelta(days=1))

    resp = client.get("/api/v1/temporal/mttr", params={"org_id": ORG, "group_by": "severity"})
    assert resp.status_code == 200
    keys = {r["severity"] for r in resp.json()["mttr"]}
    assert "high" in keys
    assert "low" in keys


def test_mttr_invalid_group_by(client):
    resp = client.get("/api/v1/temporal/mttr", params={"org_id": ORG, "group_by": "repo"})
    assert resp.status_code == 422
