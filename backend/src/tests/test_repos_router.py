"""Smoke tests for the repos REST router — endpoint shape + auth.

Mocks RepoService and settings auth to avoid DB dependency.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.repos.router import router as repos_router  # noqa: E402
from src.repos.service import RepoSummary, RepoDetail, ScanRunRow, FindingRow  # noqa: E402

_VIEWER_PERMS = {"view_findings"}

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


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


def _make_summary(asset_id: str = _FAKE_ASSET_ID, display_name: str = "acme-org/payments-api") -> RepoSummary:
    return RepoSummary(
        asset_id=asset_id,
        display_name=display_name,
        last_scanned_sha="abc1234",
        manifest_set_hash="hash1234",
        last_scanned_at=datetime(2026, 5, 30, tzinfo=timezone.utc),
        findings_count_by_severity={"critical": 1, "high": 2, "medium": 0, "low": 3},
        scanners_with_coverage=["dependencies", "secrets"],
        coverage_status="fresh",
    )


def _make_detail(asset_id: str = _FAKE_ASSET_ID, display_name: str = "acme-org/payments-api") -> RepoDetail:
    s = _make_summary(asset_id, display_name)
    return RepoDetail(
        asset_id=s.asset_id,
        display_name=s.display_name,
        last_scanned_sha=s.last_scanned_sha,
        manifest_set_hash=s.manifest_set_hash,
        last_scanned_at=s.last_scanned_at,
        findings_count_by_severity=s.findings_count_by_severity,
        scanners_with_coverage=s.scanners_with_coverage,
        coverage_status=s.coverage_status,
        source_url=None,
        scan_history=[],
        active_findings=[],
    )


# ── GET /api/v1/repos ─────────────────────────────────────────────────────────

def test_list_repos_returns_200():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.router.get_user_asset_ids", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.repos.service.RepoService.list_repos", return_value=[_make_summary()]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    assert resp.status_code == 200
    body = resp.json()
    assert "repos" in body
    assert len(body["repos"]) == 1
    assert body["repos"][0]["asset_id"] == _FAKE_ASSET_ID


def test_list_repos_shape():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.router.get_user_asset_ids", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.repos.service.RepoService.list_repos", return_value=[_make_summary()]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    repo = resp.json()["repos"][0]
    required_fields = [
        "asset_id", "display_name", "last_scanned_sha", "last_scanned_at",
        "findings_count_by_severity", "scanners_with_coverage",
        "coverage_status",
    ]
    for f in required_fields:
        assert f in repo, f"Missing field: {f}"


def test_list_repos_empty():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.router.get_user_asset_ids", new=AsyncMock(return_value=[])), \
         patch("src.repos.service.RepoService.list_repos", return_value=[]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/repos")
    assert resp.status_code == 200
    assert resp.json()["repos"] == []


def test_list_repos_passes_filters():
    captured: dict = {}

    def fake_list(asset_ids, since_days=None, has_critical=None, limit=100):
        captured.update({"since_days": since_days, "has_critical": has_critical, "limit": limit})
        return []

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.router.get_user_asset_ids", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.repos.service.RepoService.list_repos", side_effect=fake_list):
        client = TestClient(_make_app())
        client.get("/api/v1/repos?since_days=7&has_critical=true&limit=50")

    assert captured["since_days"] == 7
    assert captured["has_critical"] is True
    assert captured["limit"] == 50


# ── GET /api/v1/repos/{asset_id} ─────────────────────────────────────────────

def test_get_repo_returns_200():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=_make_detail()):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/repos/{_FAKE_ASSET_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["asset_id"] == _FAKE_ASSET_ID


def test_get_repo_detail_shape():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=_make_detail()):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/repos/{_FAKE_ASSET_ID}")
    body = resp.json()
    for f in ["scan_history", "active_findings", "default_branch"]:
        assert f in body, f"Missing field: {f}"


def test_get_repo_not_found():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", return_value=None):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/repos/{_FAKE_ASSET_ID}")
    assert resp.status_code == 404
    assert "error" in resp.json()


def test_get_repo_calls_service_with_correct_args():
    captured: dict = {}

    def fake_get(asset_id):
        captured["asset_id"] = asset_id
        return None

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.repos.service.RepoService.get_repo", side_effect=fake_get):
        client = TestClient(_make_app())
        client.get(f"/api/v1/repos/{_FAKE_ASSET_ID}")

    assert captured["asset_id"] == _FAKE_ASSET_ID
