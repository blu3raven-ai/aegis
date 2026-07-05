"""Tests for the EPSS API router endpoint shapes.

Mounts only the EPSS router on a minimal FastAPI app (no JWT middleware) so
tests are fast, isolated from auth, and free of DB dependencies.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.db.models import EpssScore
from src.epss.router import router as epss_router


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(epss_router)
    return app


def _make_score(**kwargs) -> EpssScore:
    s = EpssScore()
    s.cve = kwargs.get("cve", "CVE-2024-12345")
    s.score = kwargs.get("score", 0.85)
    s.percentile = kwargs.get("percentile", 0.95)
    s.scored_date = kwargs.get("scored_date", date(2024, 5, 13))
    s.fetched_at = kwargs.get("fetched_at", datetime(2024, 5, 13, 12, 0, tzinfo=timezone.utc))
    return s


@patch("src.epss.router._service")
def test_get_score_found(mock_svc):
    mock_svc.get_score.return_value = _make_score()
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/scores/CVE-2024-12345")
    assert resp.status_code == 200
    data = resp.json()
    assert data["cve"] == "CVE-2024-12345"
    assert data["score"] == pytest.approx(0.85)
    assert data["percentile"] == pytest.approx(0.95)
    assert data["scored_date"] == "2024-05-13"


@patch("src.epss.router._service")
def test_get_score_not_found(mock_svc):
    mock_svc.get_score.return_value = None
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/scores/CVE-9999-00000")
    assert resp.status_code == 404
    assert "EPSS feed" in resp.json()["detail"]


@patch("src.epss.router._service")
def test_top_findings(mock_svc):
    mock_svc.top_findings_by_epss.return_value = [
        {
            "finding_id": 1,
            "tool": "deps",
            "repo": "example/repo",
            "severity": "high",
            "identity_key": "abc",
            "cve": "CVE-2024-1234",
            "epss_score": 0.95,
            "epss_percentile": 0.99,
            "scored_date": "2024-05-13",
        }
    ]
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/top?org_id=example-org&limit=5")
    assert resp.status_code == 200
    data = resp.json()
    assert data["count"] == 1
    assert data["findings"][0]["cve"] == "CVE-2024-1234"
    mock_svc.top_findings_by_epss.assert_called_once_with("example-org", limit=5)


@patch("src.epss.router._service")
def test_top_missing_org(mock_svc):
    """org_id query parameter is required — 422 if missing."""
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/top")
    assert resp.status_code == 422


@patch("src.epss.router._service")
def test_top_limit_out_of_range_rejected(mock_svc):
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/top?org_id=x&limit=0")
    assert resp.status_code == 422
    resp = client.get("/api/v1/epss/top?org_id=x&limit=500")
    assert resp.status_code == 422


@patch("src.jobs.epss_refresh.refresh_epss_scores")
def test_refresh_endpoint_success(mock_refresh):
    mock_refresh.return_value = {"fetched": 100, "new": 5}
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.post("/api/v1/epss/refresh")
    assert resp.status_code == 200
    assert resp.json() == {"fetched": 100, "new": 5}


@patch("src.jobs.epss_refresh.refresh_epss_scores")
def test_refresh_endpoint_failure(mock_refresh):
    mock_refresh.side_effect = RuntimeError("upstream down")
    client = TestClient(_make_app(), raise_server_exceptions=False)
    resp = client.post("/api/v1/epss/refresh")
    assert resp.status_code == 502
    assert "EPSS refresh failed" in resp.json()["detail"]


@patch("src.epss.router._service")
def test_score_fields_serialized(mock_svc):
    mock_svc.get_score.return_value = _make_score()
    client = TestClient(_make_app(), raise_server_exceptions=True)
    resp = client.get("/api/v1/epss/scores/CVE-2024-12345")
    data = resp.json()
    for field in ("cve", "score", "percentile", "scored_date", "fetched_at"):
        assert field in data, f"Missing field: {field}"
