"""Smoke tests for /api/v1/repos/{asset_id}/scan and /api/v1/scans/{scan_id}."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.repos.router import router as repos_router  # noqa: E402
from src.scans.router import router as scans_router  # noqa: E402
from src.scans.service import ScanDetail, ScanSubmission  # noqa: E402

_WRITER_PERMS = {"view_findings", "run_scans"}
_VIEWER_PERMS = {"view_findings"}

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(repos_router)
    app.include_router(scans_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.user_org = "test-org"
        return await call_next(request)

    return app


def _fake_submission() -> ScanSubmission:
    return ScanSubmission(
        scan_id="scan-abc",
        repo_id="acme-org/repo-1",
        commit_sha="a" * 40,
        scanner_types=["dependencies"],
        status="queued",
        submitted_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
        submitted_by="admin-user",
    )


def _fake_detail() -> ScanDetail:
    return ScanDetail(
        scan_id="scan-abc",
        repo_id="acme-org/repo-1",
        commit_sha="a" * 40,
        scanner_types=["dependencies"],
        status="completed",
        submitted_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
        submitted_by="admin-user",
        started_at=datetime(2026, 6, 4, 0, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 6, 4, 0, 5, tzinfo=timezone.utc),
        finding_counts={"critical": 0, "high": 1, "medium": 2, "low": 0},
        error=None,
    )


def test_submit_scan_happy_path():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.repos.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.repos.router.submit_scan", new=AsyncMock(return_value=_fake_submission())):
        client = TestClient(_make_app())
        resp = client.post(
            f"/api/v1/repos/{_FAKE_ASSET_ID}/scan",
            json={"commit_sha": "a" * 40, "scanner_types": ["dependencies"]},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["scan_id"] == "scan-abc"
        assert body["status"] == "queued"
        assert body["submitted_at"]  # ISO string present


def test_submit_scan_invalid_sha():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_WRITER_PERMS):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/repos/{_FAKE_ASSET_ID}/scan", json={"commit_sha": "nope"})
        assert resp.status_code == 422


def test_submit_scan_unknown_scanner_type():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_WRITER_PERMS):
        client = TestClient(_make_app())
        resp = client.post(
            f"/api/v1/repos/{_FAKE_ASSET_ID}/scan",
            json={"commit_sha": "a" * 40, "scanner_types": ["bogus"]},
        )
        assert resp.status_code == 422


def test_submit_scan_repo_not_found():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_WRITER_PERMS), \
         patch("src.repos.router.resolve_asset_ids_from_request", new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.repos.router.submit_scan", new=AsyncMock(return_value=None)):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/repos/{_FAKE_ASSET_ID}/scan", json={"commit_sha": "a" * 40})
        assert resp.status_code == 404


def test_submit_scan_missing_permission():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        client = TestClient(_make_app())
        resp = client.post(f"/api/v1/repos/{_FAKE_ASSET_ID}/scan", json={"commit_sha": "a" * 40})
        assert resp.status_code == 403


def test_get_scan_happy_path():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=_fake_detail())):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["scan_id"] == "scan-abc"
        assert body["status"] == "completed"
        assert body["finding_counts"]["high"] == 1


def test_get_scan_not_found():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=None)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-missing")
        assert resp.status_code == 404


def test_get_scan_missing_org():
    """When middleware injects no user_org and no query param, 400."""
    app = FastAPI()
    app.include_router(scans_router)
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        client = TestClient(app)
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 400


def test_get_scan_surfaces_verification_summary_when_present():
    detail = _fake_detail()
    detail.verification_summary = {
        "confirmed": 2,
        "needs_verify": 1,
        "possible": 0,
        "ruled_out": 3,
        "legacy": 0,
        "tokens_in": 1234,
        "tokens_out": 567,
        "model": "claude-sonnet-4-6",
    }
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=detail)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["verification_summary"]["confirmed"] == 2
        assert body["verification_summary"]["ruled_out"] == 3
        assert body["verification_summary"]["tokens_in"] == 1234
        assert body["verification_summary"]["model"] == "claude-sonnet-4-6"


def test_get_scan_verification_summary_absent_when_legacy():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.scans.router.get_scan", new=AsyncMock(return_value=_fake_detail())):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/scans/scan-abc")
        assert resp.status_code == 200
        body = resp.json()
        assert body["verification_summary"] is None
