"""Smoke tests for the SBOM REST router — auth + asset-scope enforcement.

Mocks the MinIO and DB layers so we can verify each endpoint gates on
view_findings and rejects out-of-scope repo_ids and image digests.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.sbom.router import router as sbom_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_OTHER_ASSET_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_REPO_ID = "acme/api"
_DIGEST = "sha256:" + "a" * 64
_DIGEST_2 = "sha256:" + "b" * 64
_VIEWER_PERMS = {"view_findings"}

_FAKE_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(sbom_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    return app


# ─── /export?repo= ──────────────────────────────────────────────────────────


def test_export_repo_returns_sbom_when_in_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=True), \
         patch("src.sbom.router._latest_repo_sbom_key", return_value="dependencies/acme/auto-1/api/sbom.cdx.json"), \
         patch("src.sbom.router.download_json", return_value=_FAKE_SBOM):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/vnd.cyclonedx+json")


def test_export_repo_returns_404_when_out_of_scope():
    called = {"latest": False}

    def fake_latest(*args, **kwargs):
        called["latest"] = True
        return "dependencies/acme/auto-1/api/sbom.cdx.json"

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False), \
         patch("src.sbom.router._latest_repo_sbom_key", side_effect=fake_latest):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")

    assert resp.status_code == 404
    assert called["latest"] is False


def test_export_repo_returns_403_without_permission():
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")
    assert resp.status_code == 403


# ─── /export?image= ─────────────────────────────────────────────────────────


def test_export_image_returns_sbom_when_in_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _FAKE_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?image={_DIGEST}")
    assert resp.status_code == 200


def test_export_image_returns_404_when_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _OTHER_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?image={_DIGEST}")
    assert resp.status_code == 404


# ─── /history ───────────────────────────────────────────────────────────────


def test_history_returns_empty_when_out_of_scope():
    called = {"list": False}

    def fake_list_repo_history(*args, **kwargs):
        called["list"] = True
        return [{"run_id": "auto-1"}]

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False), \
         patch("src.sbom.router._list_repo_history", side_effect=fake_list_repo_history):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/history?repo={_REPO_ID}")

    assert resp.status_code == 200
    assert resp.json() == []
    assert called["list"] is False


def test_history_returns_entries_when_in_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=True), \
         patch("src.sbom.router._list_repo_history",
               return_value=[{"run_id": "auto-1", "created_at": None, "key": "k"}]):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/history?repo={_REPO_ID}")
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# ─── /diff ──────────────────────────────────────────────────────────────────


def test_diff_repo_returns_404_when_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False), \
         patch("src.sbom.router._fetch_sbom_by_run", return_value=_FAKE_SBOM):
        client = TestClient(_make_app())
        resp = client.get(
            f"/api/v1/sboms/diff?repo_id={_REPO_ID}&from_run_id=auto-1&to_run_id=auto-2"
        )
    assert resp.status_code == 404


def test_diff_image_returns_404_when_one_digest_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               side_effect=[
                   (_FAKE_SBOM, None, _FAKE_ASSET_ID),
                   (_FAKE_SBOM, None, _OTHER_ASSET_ID),
               ]):
        client = TestClient(_make_app())
        resp = client.get(
            f"/api/v1/sboms/diff?image_digest_from={_DIGEST}&image_digest_to={_DIGEST_2}"
        )
    assert resp.status_code == 404


# ─── Path-param aliases ─────────────────────────────────────────────────────


def test_path_repo_export_returns_404_when_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/repo/{_REPO_ID}")
    assert resp.status_code == 404


def test_path_image_export_returns_404_when_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _OTHER_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/image/{_DIGEST}")
    assert resp.status_code == 404


def test_path_repo_history_returns_empty_when_out_of_scope():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/repo/{_REPO_ID}/history")
    assert resp.status_code == 200
    assert resp.json() == []
