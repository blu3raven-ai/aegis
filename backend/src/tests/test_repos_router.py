"""Smoke tests for the repos REST router — endpoint shape + auth.

Mocks RepoService and settings auth to avoid DB dependency.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("JWT_SHARED_SECRET", "0" * 64)

from src.repos.router import router as repos_router  # noqa: E402
from src.repos.service import RepoSummary, RepoDetail, ScanRunRow, FindingRow, ChainRow  # noqa: E402

_VIEWER_PERMS = {"view_findings"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(repos_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    return app


def _make_summary(repo: str = "payments-api", org: str = "acme-org") -> RepoSummary:
    return RepoSummary(
        repo_id=f"{org}/{repo}",
        org=org,
        repo=repo,
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        last_scanned_at=datetime(2026, 5, 30, tzinfo=timezone.utc),
        findings_count_by_severity={"critical": 1, "high": 2, "medium": 0, "low": 3},
        chains_count=1,
        scanners_with_coverage=["dependencies", "secrets"],
        coverage_status="fresh",
    )


def _make_detail(repo: str = "payments-api", org: str = "acme-org") -> RepoDetail:
    s = _make_summary(repo, org)
    return RepoDetail(
        repo_id=s.repo_id,
        org=s.org,
        repo=s.repo,
        last_scanned_sha=s.last_scanned_sha,
        manifest_set_hash=s.manifest_set_hash,
        last_scanned_at=s.last_scanned_at,
        findings_count_by_severity=s.findings_count_by_severity,
        chains_count=s.chains_count,
        scanners_with_coverage=s.scanners_with_coverage,
        coverage_status=s.coverage_status,
        source_url=None,
        scan_history=[],
        active_findings=[],
        attached_chains=[],
    )


# ── GET /api/v1/repos ─────────────────────────────────────────────────────────

def test_list_repos_returns_200():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.list_repos", return_value=[_make_summary()]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    assert resp.status_code == 200
    body = resp.json()
    assert "repos" in body
    assert len(body["repos"]) == 1
    assert body["repos"][0]["repo_id"] == "acme-org/payments-api"


def test_list_repos_shape():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.list_repos", return_value=[_make_summary()]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    repo = resp.json()["repos"][0]
    required_fields = [
        "repo_id", "org", "repo", "last_scanned_sha", "last_scanned_at",
        "findings_count_by_severity", "chains_count", "scanners_with_coverage",
        "coverage_status",
    ]
    for f in required_fields:
        assert f in repo, f"Missing field: {f}"


def test_list_repos_empty():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.list_repos", return_value=[]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    assert resp.status_code == 200
    assert resp.json()["repos"] == []


def test_list_repos_passes_filters():
    captured: dict = {}

    def fake_list(org_id=None, since_days=None, has_critical=None, limit=100):
        captured.update({"org_id": org_id, "since_days": since_days,
                          "has_critical": has_critical, "limit": limit})
        return []

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.list_repos", side_effect=fake_list):
        client = TestClient(_make_app())
        client.get("/api/v1/repos?org_id=acme-org&since_days=7&has_critical=true&limit=50")

    assert captured["org_id"] == "acme-org"
    assert captured["since_days"] == 7
    assert captured["has_critical"] is True
    assert captured["limit"] == 50


# ── GET /api/v1/repos/{repo_id} ───────────────────────────────────────────────

def test_get_repo_returns_200():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=_make_detail()):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos/acme-org%2Fpayments-api")
    assert resp.status_code == 200
    body = resp.json()
    assert body["repo_id"] == "acme-org/payments-api"


def test_get_repo_detail_shape():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=_make_detail()):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos/acme-org%2Fpayments-api")
    body = resp.json()
    for f in ["scan_history", "active_findings", "attached_chains", "default_branch"]:
        assert f in body, f"Missing field: {f}"


def test_get_repo_not_found():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=None):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos/acme-org%2Fmissing")
    assert resp.status_code == 404
    assert "error" in resp.json()


def test_get_repo_bad_id_format():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=None):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos/noslash")
    assert resp.status_code == 400


def test_get_repo_calls_service_with_correct_args():
    captured: dict = {}

    def fake_get(org, repo_name):
        captured["org"] = org
        captured["repo_name"] = repo_name
        return None

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", side_effect=fake_get):
        client = TestClient(_make_app())
        client.get("/api/v1/repos/acme-org%2Fpayments-api")

    assert captured["org"] == "acme-org"
    assert captured["repo_name"] == "payments-api"
