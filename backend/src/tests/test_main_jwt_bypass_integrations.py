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

from types import SimpleNamespace

from src.main import (
    _is_dev_graphiql_request,
    _is_integrations_webhook_path,
    _propagate_session_to_state,
)


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


def test_dev_graphiql_requires_docs_env(monkeypatch):
    monkeypatch.delenv("ENABLE_BACKEND_DOCS", raising=False)
    assert _is_dev_graphiql_request("GET", "/api/v1/graphql") is False
    assert _is_dev_graphiql_request("POST", "/api/v1/graphql") is False


def test_dev_graphiql_get_passes_with_docs_env(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    assert _is_dev_graphiql_request("GET", "/api/v1/graphql") is True


def test_dev_graphiql_post_passes_with_docs_env(monkeypatch):
    """POST queries also need to bypass require_jwt so resolvers can return
    a clean UNAUTHENTICATED error instead of the bearer-token envelope."""
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    assert _is_dev_graphiql_request("POST", "/api/v1/graphql") is True


def test_dev_graphiql_rejects_other_methods(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    assert _is_dev_graphiql_request("PUT", "/api/v1/graphql") is False
    assert _is_dev_graphiql_request("DELETE", "/api/v1/graphql") is False


def test_dev_graphiql_only_matches_graphql_path(monkeypatch):
    monkeypatch.setenv("ENABLE_BACKEND_DOCS", "true")
    assert _is_dev_graphiql_request("GET", "/api/v1/findings") is False
    assert _is_dev_graphiql_request("POST", "/api/v1/findings") is False


def test_propagate_session_populates_user_sub_for_graphql_bypass():
    """Regression: the docs-mode GraphQL bypass must still forward the
    SessionAuthMiddleware-attached session onto request.state, otherwise
    authenticated resolvers see user_sub=None and raise UNAUTHENTICATED."""
    request = SimpleNamespace(state=SimpleNamespace())
    request.state.session = SimpleNamespace(
        user_id="user-123",
        user=SimpleNamespace(role_id="role-admin"),
    )
    _propagate_session_to_state(request)
    assert request.state.user_sub == "user-123"
    assert request.state.user_role_id == "role-admin"


def test_propagate_session_noop_when_no_session():
    """Unauthenticated GraphiQL hits — no session attached — must not crash and
    must not invent an identity. Resolvers will then raise UNAUTHENTICATED."""
    request = SimpleNamespace(state=SimpleNamespace())
    _propagate_session_to_state(request)
    assert not hasattr(request.state, "user_sub")
