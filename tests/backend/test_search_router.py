"""Unit tests for the global search REST endpoint.

Uses a mocked SearchService so no real DB is needed.
"""
from __future__ import annotations

import os

# Must precede any src.* imports
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.search.router import router as search_router
from src.search.service import SearchHit, SearchResults


def _make_app() -> FastAPI:
    """Minimal FastAPI app with the search router and a permissive auth stub."""
    app = FastAPI()
    app.include_router(search_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    return app


def _empty_results(query: str = "") -> SearchResults:
    return SearchResults(query=query, total=0, grouped={}, duration_ms=0)


def _results_with_hit(query: str = "cve") -> SearchResults:
    hit = SearchHit(
        type="finding",
        id="42",
        title="CVE-2023-0001",
        subtitle="payments-api · high",
        href="/dependencies/dashboard",
        score=0.7,
        metadata={"tool": "dependencies", "severity": "high"},
    )
    return SearchResults(
        query=query,
        total=1,
        grouped={"findings": [hit]},
        duration_ms=3,
    )


# ── endpoint shape tests ──────────────────────────────────────────────────────

class TestSearchEndpoint:
    def test_empty_query_returns_empty_body(self):
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/api/v1/search?q=")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 0
        assert body["grouped"] == {}

    def test_whitespace_only_query_returns_empty_body(self):
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/api/v1/search?q=   ")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_missing_q_param_returns_empty_body(self):
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/api/v1/search")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_hit_response_shape(self):
        app = _make_app()
        client = TestClient(app)

        mock_results = _results_with_hit("CVE-2023")
        with patch("src.search.router._service") as mock_svc:
            mock_svc.search.return_value = mock_results
            resp = client.get("/api/v1/search?q=CVE-2023")

        assert resp.status_code == 200
        body = resp.json()
        assert body["query"] == "CVE-2023"
        assert body["total"] == 1
        assert "findings" in body["grouped"]
        hit = body["grouped"]["findings"][0]
        assert hit["type"] == "finding"
        assert hit["id"] == "42"
        assert hit["title"] == "CVE-2023-0001"
        assert hit["href"] == "/dependencies/dashboard"
        assert "score" in hit
        assert "metadata" in hit

    def test_scope_param_forwarded_to_service(self):
        app = _make_app()
        client = TestClient(app)

        with patch("src.search.router._service") as mock_svc:
            mock_svc.search.return_value = _empty_results("cve")
            client.get("/api/v1/search?q=cve&scope=findings,chains")

        call_kwargs = mock_svc.search.call_args
        active_scopes = call_kwargs.kwargs.get("scopes") or call_kwargs[1].get("scopes") or call_kwargs[0][1]
        assert set(active_scopes) == {"findings", "chains"}

    def test_limit_param_forwarded_to_service(self):
        app = _make_app()
        client = TestClient(app)

        with patch("src.search.router._service") as mock_svc:
            mock_svc.search.return_value = _empty_results()
            client.get("/api/v1/search?q=test&limit=10")

        call_kwargs = mock_svc.search.call_args
        limit = call_kwargs.kwargs.get("limit") or call_kwargs[1].get("limit")
        assert limit == 10

    def test_invalid_limit_clamped(self):
        """limit > 200 should be rejected by FastAPI's Query validator."""
        app = _make_app()
        client = TestClient(app)
        resp = client.get("/api/v1/search?q=test&limit=999")
        assert resp.status_code == 422

    def test_unknown_scope_ignored(self):
        """Unknown scopes are dropped silently — service receives None or valid scopes only."""
        app = _make_app()
        client = TestClient(app)

        with patch("src.search.router._service") as mock_svc:
            mock_svc.search.return_value = _empty_results()
            resp = client.get("/api/v1/search?q=test&scope=unknown_scope")

        assert resp.status_code == 200
        call_kwargs = mock_svc.search.call_args
        # active_scopes should be None (all unknowns filtered → empty list → None)
        active_scopes = call_kwargs.kwargs.get("scopes") or call_kwargs[1].get("scopes")
        assert active_scopes is None

    def test_duration_ms_present_in_response(self):
        app = _make_app()
        client = TestClient(app)

        with patch("src.search.router._service") as mock_svc:
            mock_svc.search.return_value = _results_with_hit()
            resp = client.get("/api/v1/search?q=cve")

        assert "duration_ms" in resp.json()
