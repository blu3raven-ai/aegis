"""Permission and org-scoping smoke tests for /api/v1/epss."""
from __future__ import annotations

import os
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.epss.router import router as epss_router  # noqa: E402

_VIEWER_PERMS = {"view_findings"}
_ADMIN_PERMS = {"view_findings", "manage_settings"}
_NO_PERMS: set[str] = set()


def _make_app(org: str | None = "test-org") -> FastAPI:
    app = FastAPI()
    app.include_router(epss_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        if org is not None:
            request.state.user_org = org
        return await call_next(request)

    return app


def test_top_requires_view_findings():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_NO_PERMS):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/epss/top")
        assert resp.status_code == 403


def test_top_resolves_org_from_session():
    captured: dict = {}

    def _fake_top(org_id, limit):
        captured["org_id"] = org_id
        captured["limit"] = limit
        return []

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.epss.router._service.top_findings_by_epss", side_effect=_fake_top):
        client = TestClient(_make_app(org="session-org"))
        # Even though the query string asks for "evil-org", the session org wins.
        resp = client.get("/api/v1/epss/top?org_id=evil-org")
        assert resp.status_code == 200
        assert captured["org_id"] == "session-org"


def test_top_falls_back_to_query_when_no_session_org():
    captured: dict = {}

    def _fake_top(org_id, limit):
        captured["org_id"] = org_id
        return []

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.epss.router._service.top_findings_by_epss", side_effect=_fake_top):
        client = TestClient(_make_app(org=None))
        resp = client.get("/api/v1/epss/top?org_id=fallback-org")
        assert resp.status_code == 200
        assert captured["org_id"] == "fallback-org"


def test_top_400_without_any_org():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        client = TestClient(_make_app(org=None))
        resp = client.get("/api/v1/epss/top")
        assert resp.status_code == 400


def test_refresh_requires_manage_settings():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/epss/refresh")
        assert resp.status_code == 403


def test_refresh_allowed_for_admin():
    fake_result = {"inserted": 1, "updated": 0}
    with patch("src.settings.router._resolve_effective_permissions", return_value=_ADMIN_PERMS), \
         patch("src.jobs.epss_refresh.refresh_epss_scores", return_value=fake_result):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/epss/refresh")
        assert resp.status_code == 200
        assert resp.json() == fake_result
