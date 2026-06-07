from __future__ import annotations

import os
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from src.integrations.router import router as integrations_router  # noqa: E402

_EXPECTED_IDS = {
    "slack", "microsoft_teams", "pagerduty", "email_digest",
    "jira", "linear", "github_issues",
    "github_actions", "gitlab_ci", "jenkins",
    "webhook", "api_keys",
}

_SETTINGS_PERMS = {"view_settings"}


def _make_app(*, with_user: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(integrations_router)

    if with_user:
        @app.middleware("http")
        async def inject_user(request: Request, call_next):
            request.state.user_sub = "test-user"
            request.state.user_org = "test-org"
            return await call_next(request)

    return app


def test_catalog_returns_all_connectors():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=_SETTINGS_PERMS):
        resp = TestClient(app).get("/api/v1/integrations/catalog")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 12
    returned_ids = {c["id"] for c in body["connectors"]}
    assert returned_ids == _EXPECTED_IDS


def test_catalog_unauthenticated():
    # No user injected into request.state — _resolve_effective_permissions naturally
    # falls back to set() via the ValueError handler, causing require_permission to 403.
    app = _make_app(with_user=False)
    resp = TestClient(app).get("/api/v1/integrations/catalog")
    assert resp.status_code == 403


def test_catalog_no_permission():
    app = _make_app()
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = TestClient(app).get("/api/v1/integrations/catalog")
    assert resp.status_code == 403
