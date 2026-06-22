"""Permission and asset-scope tests for /api/v1/findings/decisions.

The endpoint scopes by the caller's accessible asset_ids (team grants +
direct grants), NOT by a client-supplied org_id. The legacy ``payload.
org_id`` fallback was a BOLA vector and has been removed.
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
from src.decisions.router import router as decisions_router  # noqa: E402

_FAKE_ASSET_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def _make_app(*, allow_view_findings: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(decisions_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_view_findings:
        app.dependency_overrides[Permission(VIEW_FINDINGS)] = lambda: None
    return app


def test_decisions_requires_view_findings():
    """Caller without view_findings gets 403 before any scope lookup runs."""
    called = {"scope": False}

    async def fake_scope(*args, **kwargs):
        called["scope"] = True
        return [_FAKE_ASSET_ID]

    with patch("src.authz.enforcement.dependencies.has_role_permission", return_value=False), \
         patch("src.decisions.router.resolve_asset_ids_from_request", side_effect=fake_scope):
        client = TestClient(_make_app(allow_view_findings=False))
        resp = client.post("/api/v1/findings/decisions", json={})
        assert resp.status_code == 403
        assert "view_findings" in resp.json()["detail"]
        assert called["scope"] is False


def test_decisions_uses_caller_scoped_asset_ids():
    """The service is invoked with the caller's resolved asset_ids — not any
    client-supplied org_id (which is no longer a body field)."""
    captured: dict = {}

    async def _fake_evaluate(*, asset_ids, repo, policy, session):
        captured["asset_ids"] = asset_ids
        captured["repo"] = repo
        return {"verdict": "go"}

    with patch("src.decisions.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.decisions.router._service.evaluate", new=AsyncMock(side_effect=_fake_evaluate)), \
         patch("src.decisions.router.get_session") as mock_session:
        mock_session.return_value.__aenter__ = AsyncMock(return_value=object())
        mock_session.return_value.__aexit__ = AsyncMock(return_value=False)
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/findings/decisions",
            json={"repo": "acme/api"},
        )
        assert resp.status_code == 200
        assert captured["asset_ids"] == [_FAKE_ASSET_ID]
        assert captured["repo"] == "acme/api"


def test_decisions_ignores_legacy_body_org_id():
    """The legacy ``org_id`` body field used to widen scope; today it is
    silently ignored (Pydantic extra-field policy) and the verdict is still
    computed against the caller's actual asset_ids."""
    captured: dict = {}

    async def _fake_evaluate(*, asset_ids, repo, policy, session):
        captured["asset_ids"] = asset_ids
        return {"verdict": "go"}

    with patch("src.decisions.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[_FAKE_ASSET_ID])), \
         patch("src.decisions.router._service.evaluate", new=AsyncMock(side_effect=_fake_evaluate)), \
         patch("src.decisions.router.get_session") as mock_session:
        mock_session.return_value.__aenter__ = AsyncMock(return_value=object())
        mock_session.return_value.__aexit__ = AsyncMock(return_value=False)
        client = TestClient(_make_app())
        resp = client.post(
            "/api/v1/findings/decisions",
            json={"org_id": "evil-org", "repo": "acme/api"},
        )
        assert resp.status_code == 200
        # Caller's real scope wins; the body's org_id has no effect.
        assert captured["asset_ids"] == [_FAKE_ASSET_ID]


def test_decisions_empty_scope_returns_403():
    """Caller has VIEW_FINDINGS but no asset access — 403 (fail-closed) so
    an unauthorized caller cannot fish for a 'pass' verdict against an
    empty finding set."""
    with patch("src.decisions.router.resolve_asset_ids_from_request",
               new=AsyncMock(return_value=[])), \
         patch("src.decisions.router._service.evaluate") as mock_evaluate:
        client = TestClient(_make_app())
        resp = client.post("/api/v1/findings/decisions", json={})
        assert resp.status_code == 403
        # Service must not be touched when the caller has no scope.
        mock_evaluate.assert_not_called()
