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

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import VIEW_FINDINGS  # noqa: E402
from src.sbom.router import router as sbom_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_OTHER_ASSET_ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
_REPO_ID = "acme/api"
_DIGEST = "sha256:" + "a" * 64
_DIGEST_2 = "sha256:" + "b" * 64
_VIEWER_PERMS = {"view_findings"}

_FAKE_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(sbom_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        # /download uses the declarative Depends(Permission(VIEW_FINDINGS))
        # gate; bypass it here for happy/scope-mocked paths so we can mock
        # the asset-scope and MinIO layers in isolation.
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app




def test_export_repo_returns_sbom_when_in_scope():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=True), \
         patch("src.sbom.router._latest_repo_sbom_key", return_value="dependencies_scanning/acme/auto-1/api/sbom.cdx.json"), \
         patch("src.sbom.router.download_json", return_value=_FAKE_SBOM):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/vnd.cyclonedx+json")


def test_export_repo_returns_404_when_out_of_scope():
    called = {"latest": False}

    def fake_latest(*args, **kwargs):
        called["latest"] = True
        return "dependencies_scanning/acme/auto-1/api/sbom.cdx.json"

    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False), \
         patch("src.sbom.router._latest_repo_sbom_key", side_effect=fake_latest):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")

    assert resp.status_code == 404
    assert called["latest"] is False


def test_export_repo_returns_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])):
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.get(f"/api/v1/sboms/export?repo={_REPO_ID}")
    assert resp.status_code == 403




def test_export_image_returns_sbom_when_in_scope():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _FAKE_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?image={_DIGEST}")
    assert resp.status_code == 200


def test_export_image_returns_404_when_out_of_scope():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _OTHER_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/export?image={_DIGEST}")
    assert resp.status_code == 404




def test_path_repo_export_returns_404_when_out_of_scope():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/repo/{_REPO_ID}")
    assert resp.status_code == 404


def test_path_image_export_returns_404_when_out_of_scope():
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._fetch_container_sbom_by_digest",
               return_value=(_FAKE_SBOM, None, _OTHER_ASSET_ID)):
        client = TestClient(_make_app())
        resp = client.get(f"/api/v1/sboms/image/{_DIGEST}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# /download — legacy SBOM endpoint, now scoped via resolve_asset_ids +
# _repo_in_scope (replaces the old require_orgs?org= query-param gate that
# never intersected with the caller's actual team grants).
# ---------------------------------------------------------------------------


def test_download_returns_sbom_when_repo_in_scope():
    with patch("src.sbom.router.check_feature", return_value=None), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=True), \
         patch("src.sbom.router.download_from_minio", return_value=_FAKE_SBOM):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sboms/download?org=acme&repo=api")
    assert resp.status_code == 200
    assert "attachment" in resp.headers["content-disposition"]


def test_download_returns_404_when_repo_out_of_scope():
    """BOLA test: a viewer with VIEW_FINDINGS but no team grant on acme/api
    must not get the SBOM, and MinIO must not even be queried."""
    called = {"minio": False}

    def fake_download(*args, **kwargs):
        called["minio"] = True
        return _FAKE_SBOM

    with patch("src.sbom.router.check_feature", return_value=None), \
         patch("src.sbom.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_OTHER_ASSET_ID])), \
         patch("src.sbom.router._repo_in_scope", return_value=False), \
         patch("src.sbom.router.download_from_minio", side_effect=fake_download):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/sboms/download?org=acme&repo=api")
    assert resp.status_code == 404
    assert called["minio"] is False


def test_download_returns_403_without_view_findings():
    """Permission gate fires before scope resolution or MinIO is touched."""
    called = {"scope": False, "minio": False}

    async def fake_scope(*args, **kwargs):
        called["scope"] = True
        return [_FAKE_ASSET_ID]

    def fake_minio(*args, **kwargs):
        called["minio"] = True
        return _FAKE_SBOM

    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.sbom.router.check_feature", return_value=None), \
         patch("src.sbom.router.resolve_asset_ids_from_request", side_effect=fake_scope), \
         patch("src.sbom.router.download_from_minio", side_effect=fake_minio):
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.get("/api/v1/sboms/download?org=acme&repo=api")
    assert resp.status_code == 403
    assert called["scope"] is False
    assert called["minio"] is False


