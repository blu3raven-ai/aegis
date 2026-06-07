"""Smoke tests for /api/v1/images — endpoint shape + auth.

Mocks the service to avoid DB dependency. Mocks `_resolve_effective_permissions` to
control permission outcomes (the codebase pattern; middleware does NOT set
`request.state.user_perms`).
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.images.router import router as images_router  # noqa: E402
from src.images.service import ImageListResult, ImageRowData  # noqa: E402

_VIEWER_PERMS = {"view_findings"}
_ASSET_IDS = ["asset-uuid-1"]


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(images_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    return app


def _fake_result() -> ImageListResult:
    return ImageListResult(
        images=[
            ImageRowData(
                image_digest="sha256:abc",
                image_name="registry/example",
                image_tag="v1",
                first_seen_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
                last_scanned_at=datetime(2026, 6, 3, tzinfo=timezone.utc),
                critical=2,
                high=1,
                medium=0,
                low=0,
                repos=["org/repo-1"],
            )
        ],
        next_cursor=None,
        total_count=1,
    )


def _mock_session_factory(asset_ids: list[str]):
    """Return a context-manager mock that yields a DB session returning asset_ids."""
    mock_db = AsyncMock()
    mock_cm = MagicMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_db)
    mock_cm.__aexit__ = AsyncMock(return_value=False)
    return mock_cm


def test_list_images_happy_path():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=_ASSET_IDS)), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory(_ASSET_IDS)), \
         patch("src.images.router.list_images", new=AsyncMock(return_value=_fake_result())):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images?limit=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_count"] == 1
        assert len(body["images"]) == 1
        img = body["images"][0]
        assert img["image_digest"] == "sha256:abc"
        assert img["finding_counts"]["critical"] == 2
        assert img["repos"] == ["org/repo-1"]
        assert body["next_cursor"] is None
        assert "base_image_digest" not in img
        # Enrichment fields are present and null-tolerant when not derived.
        assert "last_scanned_at" in img
        assert "layer_count" in img and img["layer_count"] is None
        assert "size_bytes" in img and img["size_bytes"] is None
        assert "base_os" in img and img["base_os"] is None


def test_list_images_last_scanned_at_populated_when_scan_exists():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=_ASSET_IDS)), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory(_ASSET_IDS)), \
         patch("src.images.router.list_images", new=AsyncMock(return_value=_fake_result())):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images")
        assert resp.status_code == 200
        img = resp.json()["images"][0]
        assert img["last_scanned_at"] == "2026-06-03T00:00:00+00:00"


def test_list_images_last_scanned_at_null_when_no_scan_history():
    result = ImageListResult(
        images=[
            ImageRowData(
                image_digest="sha256:def",
                image_name="registry/example",
                image_tag="v2",
                first_seen_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
                last_scanned_at=None,
                critical=0,
                high=0,
                medium=0,
                low=0,
                repos=[],
            )
        ],
        next_cursor=None,
        total_count=1,
    )
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=_ASSET_IDS)), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory(_ASSET_IDS)), \
         patch("src.images.router.list_images", new=AsyncMock(return_value=result)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images")
        assert resp.status_code == 200
        img = resp.json()["images"][0]
        assert img["last_scanned_at"] is None


def test_list_images_enrichment_fields_pass_through_when_present():
    """When the service surfaces non-null enrichment fields, the router echoes them."""
    result = ImageListResult(
        images=[
            ImageRowData(
                image_digest="sha256:ghi",
                image_name="registry/example",
                image_tag="v3",
                first_seen_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
                last_scanned_at=datetime(2026, 6, 4, tzinfo=timezone.utc),
                critical=0,
                high=0,
                medium=0,
                low=0,
                repos=[],
                layer_count=7,
                size_bytes=12_345_678,
                base_os="alpine:3.18",
            )
        ],
        next_cursor=None,
        total_count=1,
    )
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=_ASSET_IDS)), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory(_ASSET_IDS)), \
         patch("src.images.router.list_images", new=AsyncMock(return_value=result)):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images")
        assert resp.status_code == 200
        img = resp.json()["images"][0]
        assert img["layer_count"] == 7
        assert img["size_bytes"] == 12_345_678
        assert img["base_os"] == "alpine:3.18"


def test_list_images_invalid_cursor():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=_ASSET_IDS)), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory(_ASSET_IDS)), \
         patch("src.images.router.list_images", new=AsyncMock(side_effect=ValueError("Invalid cursor"))):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images?cursor=not-base64")
        assert resp.status_code == 400


def test_list_images_missing_permission():
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images")
        assert resp.status_code == 403


def test_list_images_no_assets():
    """With no accessible assets, return an empty 200 instead of erroring."""
    empty = ImageListResult(images=[], next_cursor=None, total_count=0)
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.images.router.get_user_asset_ids", new=AsyncMock(return_value=[])), \
         patch("src.images.router.async_session_factory", return_value=_mock_session_factory([])), \
         patch("src.images.router.list_images", new=AsyncMock(return_value=empty)) as mock_list:
        client = TestClient(_make_app())
        resp = client.get("/api/v1/images")
        assert resp.status_code == 200
        body = resp.json()
        assert body["total_count"] == 0
        assert body["images"] == []
        # Service is still invoked with the empty asset_ids list so the short-circuit
        # lives in one place (the service) rather than being duplicated here.
        mock_list.assert_awaited_once()
        kwargs = mock_list.await_args.kwargs
        assert kwargs["asset_ids"] == []
