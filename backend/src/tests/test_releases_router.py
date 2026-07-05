"""Tests for the releases REST router.

Covers the list and detail endpoints: scope fail-closure, cursor pass-through,
limit clamping, ValueError → 400 mapping, missing scan → 404.
"""
from __future__ import annotations

import os
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.history.releases.router import router as releases_router  # noqa: E402
from src.history.releases.service import (  # noqa: E402
    MAX_LIMIT,
    BlockerDiffRowData,
    ReleaseDetailRow,
    ReleaseRow,
)
from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(releases_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def _patch_scope(asset_ids: list[str]):
    return patch(
        "src.history.releases.router.resolve_asset_ids_from_request",
        new=AsyncMock(return_value=asset_ids),
    )


def _fake_run_db(coro_fn):
    """Invoke the router's inner coroutine on a fresh loop in a worker thread.

    The real run_db ships work to a dedicated background loop with its own
    session pool. For tests we just need the coroutine to execute — the inner
    list_releases / get_release calls are already mocked, so the session arg
    is ignored.
    """
    import asyncio
    import concurrent.futures

    def _thread() -> object:
        return asyncio.run(coro_fn(None))

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_thread).result()


def _summary_dict() -> dict:
    return {
        "scan_id": "scan-1",
        "repo_id": "acme/api",
        "repo": "api",
        "ref": "main",
        "commit_sha": "abc123def4567890",
        "short_sha": "abc123d",
        "verdict": "go",
        "blocker_count": 0,
        "warn_count": 1,
        "scanner_count": 3,
        "status": "completed",
        "started_at": "2026-01-01T00:00:00+00:00",
        "finished_at": "2026-01-01T00:05:00+00:00",
        "triggered_by": {
            "actor_type": "user",
            "actor_id": "user-1",
            "display_name": "alice",
        },
    }


# ── list ───────────────────────────────────────────────────────────────────


def test_list_returns_empty_page_when_scope_is_empty():
    with _patch_scope([]):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/history/releases")

    assert resp.status_code == 200
    assert resp.json() == {"releases": [], "next_cursor": None}


def test_list_clamps_oversized_limit_before_calling_service():
    captured: dict = {}

    async def fake_list_releases(filters, session):
        captured["limit"] = filters.limit
        return {"releases": [], "next_cursor": None}

    with _patch_scope(["asset-1"]), patch(
        "src.history.releases.router.list_releases",
        new=fake_list_releases,
    ), patch(
        "src.history.releases.router.run_db",
        side_effect=_fake_run_db,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/history/releases?limit=9999")

    assert resp.status_code == 200
    assert captured["limit"] == MAX_LIMIT


def test_list_forwards_filters_and_cursor_to_service():
    captured: dict = {}

    async def fake_list_releases(filters, session):
        captured["asset_ids"] = filters.asset_ids
        captured["repo_id"] = filters.repo_id
        captured["status"] = filters.status
        captured["verdict"] = filters.verdict
        captured["cursor"] = filters.cursor
        return {"releases": [_summary_dict()], "next_cursor": "next-x"}

    with _patch_scope(["asset-1", "asset-2"]), patch(
        "src.history.releases.router.list_releases",
        new=fake_list_releases,
    ), patch(
        "src.history.releases.router.run_db",
        side_effect=_fake_run_db,
    ):
        client = TestClient(_make_app())
        resp = client.get(
            "/api/v1/history/releases?repo_id=acme/api&status=completed&verdict=go&cursor=abc"
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["next_cursor"] == "next-x"
    assert len(body["releases"]) == 1
    assert captured == {
        "asset_ids": ["asset-1", "asset-2"],
        "repo_id": "acme/api",
        "status": "completed",
        "verdict": "go",
        "cursor": "abc",
    }


def test_list_maps_service_value_error_to_400():
    async def fake_list_releases(filters, session):
        raise ValueError("invalid cursor payload")

    with _patch_scope(["asset-1"]), patch(
        "src.history.releases.router.list_releases",
        new=fake_list_releases,
    ), patch(
        "src.history.releases.router.run_db",
        side_effect=_fake_run_db,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/history/releases?cursor=bad")

    assert resp.status_code == 400
    assert "invalid cursor" in resp.json()["detail"]


# ── detail ────────────────────────────────────────────────────────────────


def test_detail_returns_404_when_release_missing_or_out_of_scope():
    async def fake_get_release(*, scan_id, asset_ids, session):
        return None

    with _patch_scope(["asset-1"]), patch(
        "src.history.releases.router.get_release",
        new=fake_get_release,
    ), patch(
        "src.history.releases.router.run_db",
        side_effect=_fake_run_db,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/history/releases/scan-missing")

    assert resp.status_code == 404


def test_detail_flattens_summary_and_includes_diff_arrays():
    summary = ReleaseRow(**_summary_dict())
    diff_row = BlockerDiffRowData(
        finding_id=42,
        diff_status="new",
        severity="critical",
        title="path traversal",
        file_path="src/handler.py",
        cve_id="CVE-2026-1",
        cwe_id="CWE-22",
        scanner="code_scanning",
        first_seen_at="2026-01-01T00:00:00+00:00",
        introduced_by_commit_sha="abc123",
        is_kev=False,
        epss_score=0.5,
    )
    detail = ReleaseDetailRow(
        summary=summary,
        baseline_scan_id="scan-0",
        baseline_ref="main@9876543",
        baseline_taken_at="2025-12-31T00:00:00+00:00",
        scanners_run=["code_scanning", "secrets_scanning"],
        blockers_diff=[diff_row],
        improvements=[],
    )

    async def fake_get_release(*, scan_id, asset_ids, session):
        return detail

    with _patch_scope(["asset-1"]), patch(
        "src.history.releases.router.get_release",
        new=fake_get_release,
    ), patch(
        "src.history.releases.router.run_db",
        side_effect=_fake_run_db,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/history/releases/scan-1")

    assert resp.status_code == 200
    body = resp.json()
    # Summary fields are flattened onto the root response
    assert body["scan_id"] == "scan-1"
    assert body["verdict"] == "go"
    assert body["triggered_by"] == {
        "actor_type": "user",
        "actor_id": "user-1",
        "display_name": "alice",
    }
    # Detail extras
    assert body["baseline_scan_id"] == "scan-0"
    assert body["scanners_run"] == ["code_scanning", "secrets_scanning"]
    assert body["blockers_diff"] == [asdict(diff_row)]
    assert body["improvements"] == []
