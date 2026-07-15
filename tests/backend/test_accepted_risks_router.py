"""Tests permission (403) + object-scope (404 / empty) gates on /api/v1/accepted-risks."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import MANAGE_SOURCES
from src.sources.accepted_risks_router import router as accepted_risks_router


def _make_app(*, allow_manage_sources: bool = True) -> FastAPI:
    app = FastAPI()
    app.include_router(accepted_risks_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "viewer"
        request.state.user_role_id = None
        return await call_next(request)

    if allow_manage_sources:
        app.dependency_overrides[Permission(MANAGE_SOURCES)] = lambda: None
    return app


def test_create_requires_manage_sources():
    with patch(
        "src.authz.enforcement.dependencies.has_role_permission",
        return_value=False,
    ):
        client = TestClient(_make_app(allow_manage_sources=False))
        resp = client.post("/api/v1/accepted-risks", json={"statement": "known false positive"})

    assert resp.status_code == 403


def test_list_empty_scope_returns_empty():
    with patch(
        "src.sources.accepted_risks_router.resolve_asset_ids_from_request",
        AsyncMock(return_value=[]),
    ):
        client = TestClient(_make_app())
        resp = client.get("/api/v1/accepted-risks")

    assert resp.status_code == 200
    assert resp.json() == {"acceptedRisks": []}


def test_get_out_of_scope_is_404():
    # Admin holds manage_sources but the risk's asset is not in their scope:
    # get_scoped returns None → 404 (never 403 for object-level miss).
    with (
        patch(
            "src.sources.accepted_risks_router.resolve_asset_ids_from_request",
            AsyncMock(return_value=["asset-in-scope"]),
        ),
        patch(
            "src.sources.accepted_risks_router.svc.get_scoped",
            AsyncMock(return_value=None),
        ),
    ):
        client = TestClient(_make_app())
        resp = client.patch("/api/v1/accepted-risks/999", json={"enabled": False})

    assert resp.status_code == 404
