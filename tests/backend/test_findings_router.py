"""Integration tests for GET /api/v1/findings.

The router delegates to list_findings(), which is exercised by the service
tests against a fake session. Here we patch the service entry point so we
focus on HTTP-level concerns: query param parsing, validation errors, cursor
round-trip through the URL, and the response envelope.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from src.findings.router import router as findings_router  # noqa: E402


def _make_app() -> TestClient:
    app = FastAPI()
    app.include_router(findings_router)

    @app.middleware("http")
    async def inject_state(request: Request, call_next):
        request.state.user_sub = "test-user"
        request.state.user_role = "owner"
        return await call_next(request)

    return TestClient(app, raise_server_exceptions=True)


def _sample_response() -> dict:
    return {
        "findings": [
            {
                "id": "1",
                "scanner": "deps",
                "severity": "critical",
                "state": "open",
                "title": "log4j RCE",
                "cve": "CVE-2021-44228",
                "package": "log4j@2.14.0",
                "file_path": None,
                "line": None,
                "repo": "acme-org/api",
                "org_id": "acme-org",
                "created_at": "2026-01-01T00:00:00+00:00",
                "updated_at": "2026-01-02T00:00:00+00:00",
            }
        ],
        "next_cursor": None,
        "total_count": 1,
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_list_findings_returns_200_with_envelope():
    client = _make_app()
    with patch("src.findings.router.list_findings", new_callable=AsyncMock) as svc:
        svc.return_value = _sample_response()
        resp = client.get("/api/v1/findings", params={"org_id": "acme-org"})
    assert resp.status_code == 200
    body = resp.json()
    assert "findings" in body
    assert "next_cursor" in body
    assert "total_count" in body
    assert body["findings"][0]["scanner"] == "deps"


def test_list_findings_empty_state():
    client = _make_app()
    empty = {"findings": [], "next_cursor": None, "total_count": 0}
    with patch("src.findings.router.list_findings", new_callable=AsyncMock) as svc:
        svc.return_value = empty
        resp = client.get("/api/v1/findings", params={"org_id": "acme-org"})
    assert resp.status_code == 200
    assert resp.json() == empty


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def test_missing_org_id_returns_422():
    """FastAPI returns 422 when a required Query is missing."""
    client = _make_app()
    resp = client.get("/api/v1/findings")
    assert resp.status_code == 422


def test_invalid_severity_returns_400():
    client = _make_app()
    with patch("src.findings.router.list_findings", new_callable=AsyncMock) as svc:
        svc.side_effect = ValueError("invalid severity: ['bogus']")
        resp = client.get(
            "/api/v1/findings",
            params={"org_id": "acme-org", "severity": "bogus"},
        )
    assert resp.status_code == 400
    assert "severity" in resp.json()["detail"]


def test_invalid_cursor_returns_400():
    client = _make_app()
    with patch("src.findings.router.list_findings", new_callable=AsyncMock) as svc:
        svc.side_effect = ValueError("invalid cursor")
        resp = client.get(
            "/api/v1/findings",
            params={"org_id": "acme-org", "cursor": "garbage"},
        )
    assert resp.status_code == 400


def test_limit_above_max_returns_422():
    """The route declares le=200 — FastAPI validates and returns 422."""
    client = _make_app()
    resp = client.get(
        "/api/v1/findings",
        params={"org_id": "acme-org", "limit": 1000},
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Filter pass-through
# ---------------------------------------------------------------------------


def test_csv_filters_are_split_into_lists():
    client = _make_app()
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return _sample_response()

    with patch("src.findings.router.list_findings", side_effect=_capture):
        resp = client.get(
            "/api/v1/findings",
            params={
                "org_id": "acme-org",
                "severity": "critical,high",
                "scanner": "deps,sast",
                "state": "open,closed",
            },
        )
    assert resp.status_code == 200
    f = captured["filters"]
    assert f.severity == ["critical", "high"]
    assert f.scanner == ["deps", "sast"]
    assert f.state == ["open", "closed"]


def test_q_and_cve_pass_through_verbatim():
    client = _make_app()
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return _sample_response()

    with patch("src.findings.router.list_findings", side_effect=_capture):
        client.get(
            "/api/v1/findings",
            params={
                "org_id": "acme-org",
                "q": "log4j",
                "cve": "CVE-2021-44228",
            },
        )
    assert captured["filters"].q == "log4j"
    assert captured["filters"].cve == "CVE-2021-44228"


def test_sort_and_direction_pass_through():
    client = _make_app()
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return _sample_response()

    with patch("src.findings.router.list_findings", side_effect=_capture):
        client.get(
            "/api/v1/findings",
            params={"org_id": "acme-org", "sort": "created_at", "direction": "asc"},
        )
    assert captured["filters"].sort == "created_at"
    assert captured["filters"].direction == "asc"


def test_empty_csv_filter_treated_as_none():
    client = _make_app()
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return _sample_response()

    with patch("src.findings.router.list_findings", side_effect=_capture):
        client.get(
            "/api/v1/findings",
            params={"org_id": "acme-org", "severity": ""},
        )
    assert captured["filters"].severity is None


# ---------------------------------------------------------------------------
# Cursor round-trip — the client must be able to pass next_cursor back to us
# ---------------------------------------------------------------------------


def test_cursor_round_trip_through_url():
    client = _make_app()
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return _sample_response()

    cursor_value = "eyJyYW5rIjogNCwgImlkIjogMTAwfQ"
    with patch("src.findings.router.list_findings", side_effect=_capture):
        client.get(
            "/api/v1/findings",
            params={"org_id": "acme-org", "cursor": cursor_value},
        )
    assert captured["filters"].cursor == cursor_value
