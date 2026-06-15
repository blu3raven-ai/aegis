"""Permission and org-scoping smoke tests for /api/v1/decisions/go-no-go."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.decisions.router import router as decisions_router  # noqa: E402

_VIEWER_PERMS = {"view_findings"}
_NO_PERMS: set[str] = set()


def _make_app(org: str | None = "test-org") -> FastAPI:
    app = FastAPI()
    app.include_router(decisions_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        if org is not None:
            request.state.user_org = org
        return await call_next(request)

    return app


def test_go_no_go_requires_view_findings():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_NO_PERMS):
        client = TestClient(_make_app())
        resp = client.post("/api/v1/decisions/go-no-go", json={})
        assert resp.status_code == 403


def test_go_no_go_session_org_wins_over_body():
    captured: dict = {}

    async def _fake_evaluate(*, org_id, repo, policy, session):
        captured["org_id"] = org_id
        return {"verdict": "go", "org_id": org_id}

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.decisions.router._service.evaluate", new=AsyncMock(side_effect=_fake_evaluate)), \
         patch("src.decisions.router.get_session") as mock_session:
        mock_session.return_value.__aenter__ = AsyncMock(return_value=object())
        mock_session.return_value.__aexit__ = AsyncMock(return_value=False)
        client = TestClient(_make_app(org="session-org"))
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "evil-org"},
        )
        assert resp.status_code == 200
        assert captured["org_id"] == "session-org"


def test_go_no_go_falls_back_to_body_org_when_no_session_org():
    captured: dict = {}

    async def _fake_evaluate(*, org_id, repo, policy, session):
        captured["org_id"] = org_id
        return {"verdict": "go"}

    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS), \
         patch("src.decisions.router._service.evaluate", new=AsyncMock(side_effect=_fake_evaluate)), \
         patch("src.decisions.router.get_session") as mock_session:
        mock_session.return_value.__aenter__ = AsyncMock(return_value=object())
        mock_session.return_value.__aexit__ = AsyncMock(return_value=False)
        client = TestClient(_make_app(org=None))
        resp = client.post(
            "/api/v1/decisions/go-no-go",
            json={"org_id": "ci-org"},
        )
        assert resp.status_code == 200
        assert captured["org_id"] == "ci-org"


def test_go_no_go_400_when_no_org_anywhere():
    with patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS):
        client = TestClient(_make_app(org=None))
        resp = client.post("/api/v1/decisions/go-no-go", json={})
        assert resp.status_code == 400
