"""Smoke tests for /api/v1/releases — list + detail with blocker diff."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.releases.router import router as releases_router  # noqa: E402
from src.releases.service import (  # noqa: E402
    BlockerDiffRowData,
    ReleaseDetailRow,
    ReleaseRow,
)

_VIEWER_PERMS = {"view_findings"}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(releases_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "alice"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.user_org = "test-org"
        return await call_next(request)

    return app


async def _resolve_assets(_request):
    return ["asset-1", "asset-2"]


async def _resolve_no_assets(_request):
    return []


@asynccontextmanager
async def _mock_session():
    """Stand-in for src.db.engine.get_session — yields a MagicMock session.

    The service functions are mocked at the router import path, so the session
    object is never actually used by SQLAlchemy in these tests.
    """
    yield MagicMock()


def _summary_dict(**overrides):
    base = {
        "scan_id": "scan-1",
        "repo_id": "test-org/repo-1",
        "repo": "repo-1",
        "ref": "main",
        "commit_sha": "a" * 40,
        "short_sha": "a" * 7,
        "verdict": "go",
        "blocker_count": 0,
        "warn_count": 0,
        "scanner_count": 4,
        "status": "completed",
        "started_at": "2026-06-04T12:00:00+00:00",
        "finished_at": "2026-06-04T12:05:00+00:00",
        "triggered_by": {"actor_type": "user", "actor_id": "alice", "display_name": "alice"},
    }
    base.update(overrides)
    return base


def _diff_row(
    finding_id: int,
    diff_status: str = "new",
    severity: str = "critical",
    title: str = "t",
    cve_id: str | None = None,
    is_kev: bool = False,
) -> BlockerDiffRowData:
    return BlockerDiffRowData(
        finding_id=finding_id,
        diff_status=diff_status,
        severity=severity,
        title=title,
        file_path=None,
        cve_id=cve_id,
        cwe_id=None,
        scanner="trivy",
        first_seen_at="2026-06-01T00:00:00+00:00",
        introduced_by_commit_sha=None,
        is_kev=is_kev,
        epss_score=None,
    )


def _detail_row(
    *,
    verdict: str = "go",
    critical: int = 0,
    high: int = 0,
    blockers: tuple[BlockerDiffRowData, ...] = (),
    improvements: tuple[BlockerDiffRowData, ...] = (),
    baseline_scan_id: str | None = None,
    baseline_ref: str | None = None,
    baseline_taken_at: str | None = None,
) -> ReleaseDetailRow:
    return ReleaseDetailRow(
        summary=ReleaseRow(
            scan_id="scan-1",
            repo_id="test-org/repo-1",
            repo="repo-1",
            ref="main",
            commit_sha="a" * 40,
            short_sha="a" * 7,
            verdict=verdict,
            blocker_count=critical,
            warn_count=high,
            scanner_count=4,
            status="completed",
            started_at="2026-06-04T12:00:00+00:00",
            finished_at="2026-06-04T12:05:00+00:00",
            triggered_by={"actor_type": "user", "actor_id": "alice", "display_name": "alice"},
        ),
        baseline_scan_id=baseline_scan_id,
        baseline_ref=baseline_ref,
        baseline_taken_at=baseline_taken_at,
        scanners_run=["dependencies", "code_scanning"],
        blockers_diff=list(blockers),
        improvements=list(improvements),
    )


# ── LIST ──────────────────────────────────────────────────────────────────────


def test_list_releases_filters_by_repo_id():
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return {"releases": [_summary_dict()], "next_cursor": None}

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.list_releases", new=AsyncMock(side_effect=_capture)),
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/releases", params={"repo_id": "test-org/repo-1"}
        )

    assert resp.status_code == 200, resp.text
    assert captured["filters"].repo_id == "test-org/repo-1"
    assert captured["filters"].asset_ids == ["asset-1", "asset-2"]
    body = resp.json()
    assert len(body["releases"]) == 1
    assert body["releases"][0]["repo_id"] == "test-org/repo-1"


def test_list_releases_ignores_legacy_org_id_query_param():
    """Legacy ?org_id=... param must not influence scoping — it's silently dropped."""
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return {"releases": [], "next_cursor": None}

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.list_releases", new=AsyncMock(side_effect=_capture)),
    ):
        resp = TestClient(_make_app()).get(
            "/api/v1/releases", params={"org_id": "other-org"}
        )

    assert resp.status_code == 200
    assert captured["filters"].asset_ids == ["asset-1", "asset-2"]


def test_list_releases_empty_assets_returns_empty():
    """Viewer with no team access (empty asset_ids) sees no releases — fail-closed."""
    captured = {}

    async def _capture(filters, session):
        captured["filters"] = filters
        return {"releases": [], "next_cursor": None}

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_no_assets),
        patch("src.releases.router.list_releases", new=AsyncMock(side_effect=_capture)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases")

    assert resp.status_code == 200
    assert captured["filters"].asset_ids == []
    assert resp.json()["releases"] == []


def test_list_releases_pagination_cursor():
    captured: list = []

    async def _capture(filters, session):
        captured.append(filters)
        # First page returns a next_cursor; second page returns none.
        if filters.cursor is None:
            return {"releases": [_summary_dict()], "next_cursor": "abc"}
        return {
            "releases": [_summary_dict(scan_id="scan-2")],
            "next_cursor": None,
        }

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.list_releases", new=AsyncMock(side_effect=_capture)),
    ):
        client = TestClient(_make_app())
        first = client.get("/api/v1/releases")
        assert first.status_code == 200
        assert first.json()["next_cursor"] == "abc"

        second = client.get("/api/v1/releases", params={"cursor": "abc"})
        assert second.status_code == 200
        assert second.json()["next_cursor"] is None

    assert len(captured) == 2
    assert captured[0].cursor is None
    assert captured[1].cursor == "abc"


def test_list_releases_rejects_bad_cursor():
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch(
            "src.releases.router.list_releases",
            new=AsyncMock(side_effect=ValueError("invalid cursor")),
        ),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases", params={"cursor": "garbage"})

    assert resp.status_code == 400
    assert "invalid cursor" in resp.json()["detail"]


def test_list_releases_missing_permission():
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(_make_app()).get("/api/v1/releases")

    assert resp.status_code == 403


# ── DETAIL ────────────────────────────────────────────────────────────────────


def test_get_release_verdict_no_go_when_critical():
    row = _detail_row(
        verdict="no_go",
        critical=1,
        blockers=(_diff_row(1, "new", "critical"),),
        baseline_scan_id="scan-baseline",
        baseline_ref="main@bbbbbbb",
        baseline_taken_at="2026-06-03T12:00:00+00:00",
    )

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=row)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-1")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "no_go"
    assert body["blocker_count"] == 1
    assert len(body["blockers_diff"]) == 1
    assert body["blockers_diff"][0]["severity"] == "critical"


def test_get_release_verdict_warn_when_high_only():
    row = _detail_row(
        verdict="warn",
        critical=0,
        high=2,
        blockers=(),
        baseline_scan_id="scan-baseline",
        baseline_ref="main@bbbbbbb",
        baseline_taken_at="2026-06-03T12:00:00+00:00",
    )

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=row)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-1")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "warn"
    assert body["warn_count"] == 2
    assert body["blockers_diff"] == []


def test_get_release_verdict_go_when_no_blockers():
    row = _detail_row(verdict="go", critical=0, high=0, blockers=(), improvements=())

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=row)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-1")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == "go"
    assert body["blockers_diff"] == []
    assert body["improvements"] == []


def test_get_release_diff_marks_new_persisted_gone_fixed_correctly():
    blockers = (
        _diff_row(1, "new", "critical", title="new-finding"),
        _diff_row(2, "persisted", "critical", title="persisted-finding"),
        _diff_row(3, "gone", "critical", title="gone-finding"),
    )
    improvements = (_diff_row(4, "fixed", "critical", title="fixed-finding"),)
    row = _detail_row(
        verdict="no_go",
        critical=2,
        blockers=blockers,
        improvements=improvements,
        baseline_scan_id="scan-baseline",
        baseline_ref="main@bbbbbbb",
        baseline_taken_at="2026-06-03T12:00:00+00:00",
    )

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=row)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-1")

    assert resp.status_code == 200, resp.text
    body = resp.json()

    by_id = {r["finding_id"]: r["diff_status"] for r in body["blockers_diff"]}
    assert by_id == {1: "new", 2: "persisted", 3: "gone"}

    improvement_by_id = {r["finding_id"]: r["diff_status"] for r in body["improvements"]}
    assert improvement_by_id == {4: "fixed"}


def test_get_release_no_baseline_marks_all_new():
    row = _detail_row(
        verdict="no_go",
        critical=2,
        blockers=(
            _diff_row(1, "new", "critical"),
            _diff_row(2, "new", "critical"),
        ),
        baseline_scan_id=None,
        baseline_ref=None,
        baseline_taken_at=None,
    )

    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=row)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-1")

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["baseline_scan_id"] is None
    assert body["baseline_ref"] is None
    assert body["baseline_taken_at"] is None
    assert len(body["blockers_diff"]) == 2
    assert all(r["diff_status"] == "new" for r in body["blockers_diff"])


def test_get_release_404_when_not_found():
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=None)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-missing")

    assert resp.status_code == 404


def test_get_release_404_out_of_scope():
    """Out-of-scope access surfaces as 404 (not 403) to avoid leaking access boundaries.

    The service returns None for scans that don't belong to the caller's accessible
    assets, which the router maps to the same 404 used for genuinely missing scans.
    """
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.releases.router.get_session", _mock_session),
        patch("src.releases.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
        patch("src.releases.router.get_release", new=AsyncMock(return_value=None)),
    ):
        resp = TestClient(_make_app()).get("/api/v1/releases/scan-other-team")

    assert resp.status_code == 404
