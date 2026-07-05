"""Tests for GET /api/v1/findings/summary."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import REVIEW_FINDINGS  # noqa: E402
from src.findings.router import router as findings_router  # noqa: E402
from src.findings.service import FIXED_WINDOW_DAYS  # noqa: E402

_VIEW_PERMS = {"review_findings"}
_NO_PERMS: set[str] = set()
_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_app(*, allow_review_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(findings_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "viewer-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_review_findings:
        app.dependency_overrides[Permission(REVIEW_FINDINGS)] = lambda: None
    return app


def test_get_summary_returns_counts_for_viewer_with_scope():
    payload = {
        "open": 5,
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "fixed_recent": 3,
        "dismissed": 4,
        "fixed_window_days": FIXED_WINDOW_DAYS,
    }
    with (
        patch(
            "src.findings.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[_FAKE_ASSET_ID]),
        ),
        patch(
            "src.findings.router.get_session",
            return_value=_NullSession(),
        ),
        patch(
            "src.findings.router.summarize_findings",
            new=AsyncMock(return_value=payload),
        ) as mock_summary,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/summary")

    assert resp.status_code == 200
    assert resp.json() == payload
    mock_summary.assert_awaited_once()


def test_get_summary_returns_zeros_when_scope_is_empty():
    with (
        patch(
            "src.findings.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "src.findings.router.summarize_findings",
            new=AsyncMock(),
        ) as mock_summary,
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/findings/summary")

    assert resp.status_code == 200
    assert resp.json() == {
        "open": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "fixed_recent": 0,
        "dismissed": 0,
        "fixed_window_days": FIXED_WINDOW_DAYS,
    }
    # Empty scope must short-circuit before any DB aggregation runs — otherwise
    # we'd issue a no-op query per request and mask a regression in the gate.
    mock_summary.assert_not_called()


def test_get_summary_rejects_caller_without_review_findings_with_403():
    with (
        patch(
            "src.authz.enforcement.dependencies.has_role_permission",
            return_value=False,
        ),
        patch(
            "src.findings.router.resolve_asset_ids_from_request",
            new=AsyncMock(return_value=[_FAKE_ASSET_ID]),
        ),
        patch(
            "src.findings.router.summarize_findings",
            new=AsyncMock(),
        ) as mock_summary,
    ):
        client = TestClient(_make_app(allow_review_findings=False))
        resp = client.get("/api/v1/findings/summary")

    assert resp.status_code == 403
    mock_summary.assert_not_called()


class _NullSession:
    """Stand-in async context manager so the handler can `async with get_session()`."""

    async def __aenter__(self):
        return None

    async def __aexit__(self, *args):
        return None
