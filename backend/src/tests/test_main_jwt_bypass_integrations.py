"""The JWT-bypass for /integrations/* must be scoped to the receiver routes.

Before this PR, ``path.startswith("/integrations/")`` skipped JWT for any
future admin/list route mounted under that prefix. Now the bypass is gated
by ``path.endswith("/webhook")`` so:

  * POST /integrations/github/webhook  -> bypasses the JWT gate
  * GET  /integrations/github/configs  -> still rejected by the auth gate

The test imports the production predicate from ``src.main`` and wires it
into a bare FastAPI app, so any change to the real implementation flows
through here. Standing up the full ``src.main.app`` for a routing check
would pull in DB and runtime side effects we don't need to exercise.
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from src.main import _is_integrations_webhook_path


def _build_app() -> FastAPI:
    app = FastAPI()

    @app.middleware("http")
    async def require_jwt(request: Request, call_next):
        if _is_integrations_webhook_path(request.url.path):
            return await call_next(request)
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized: Bearer token required"},
            )
        return await call_next(request)

    @app.post("/integrations/github/webhook")
    async def gh_webhook() -> dict:
        return {"ok": True}

    @app.post("/integrations/gitlab/webhook")
    async def gl_webhook() -> dict:
        return {"ok": True}

    @app.post("/integrations/bitbucket/webhook")
    async def bb_webhook() -> dict:
        return {"ok": True}

    @app.get("/integrations/github/configs")
    async def gh_configs() -> dict:
        return {"ok": True}

    @app.get("/integrations/admin/list")
    async def admin_list() -> dict:
        return {"ok": True}

    return app


def test_predicate_matches_only_provider_webhook_paths():
    assert _is_integrations_webhook_path("/integrations/github/webhook") is True
    assert _is_integrations_webhook_path("/integrations/gitlab/webhook") is True
    assert _is_integrations_webhook_path("/integrations/bitbucket/webhook") is True


def test_predicate_rejects_non_webhook_integrations_paths():
    assert _is_integrations_webhook_path("/integrations/github/configs") is False
    assert _is_integrations_webhook_path("/integrations/admin/list") is False
    assert _is_integrations_webhook_path("/integrations/github/webhook/extra") is False
    assert _is_integrations_webhook_path("/api/v1/integrations/github/webhook") is False
    assert _is_integrations_webhook_path("/integrations/") is False


def test_webhook_route_bypasses_jwt():
    client = TestClient(_build_app())
    resp = client.post("/integrations/github/webhook", json={})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_non_webhook_integrations_route_still_requires_auth():
    client = TestClient(_build_app())
    resp = client.get("/integrations/github/configs")
    assert resp.status_code == 401
    assert resp.json()["error"] == "Unauthorized: Bearer token required"


def test_non_webhook_integrations_route_passes_with_bearer():
    client = TestClient(_build_app())
    resp = client.get(
        "/integrations/github/configs",
        headers={"Authorization": "Bearer fake-token"},
    )
    assert resp.status_code == 200


def test_admin_list_route_under_integrations_requires_auth():
    """Probe a future admin/list-style route to lock in that only `/webhook`
    suffix routes bypass the JWT gate."""
    client = TestClient(_build_app())
    resp = client.get("/integrations/admin/list")
    assert resp.status_code == 401
