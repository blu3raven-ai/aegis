"""Tests for the license router.

The status endpoint aggregates usage counts across several internal helpers;
this file pins those wiring contracts so a moved/renamed helper can't break
the endpoint silently again.
"""
from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission
from src.authz.permissions.catalog import VIEW_SETTINGS
from src.license.router import router as license_router


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(license_router)
    # /license/status is gated on VIEW_SETTINGS; these tests cover the
    # usage-aggregation wiring, not the permission gate itself.
    app.dependency_overrides[Permission(VIEW_SETTINGS)] = lambda: None
    return app


def test_status_aggregates_usage_counts():
    with (
        patch(
            "src.auth.workspace.users_router.list_users_internal",
            return_value=[
                {"id": "u1", "status": "active"},
                {"id": "u2", "status": "active"},
                {"id": "u3", "status": "disabled"},
            ],
        ),
        patch("src.sources.store.list_connections", return_value=[1, 2]),
        patch("src.authz.teams.service.list_teams", return_value=[{"id": "t1"}]),
        patch(
            "src.authz.roles.service.list_roles",
            return_value=[
                {"id": "r1", "isSystem": True},
                {"id": "r2", "isSystem": False},
            ],
        ),
        patch(
            "src.runner.registry.list_runners_with_status",
            return_value=[
                {"id": "rn1", "status": "approved"},
                {"id": "rn2", "status": "pending"},
            ],
        ),
    ):
        client = TestClient(_make_app())
        r = client.get("/api/v1/license/status")

    assert r.status_code == 200
    body = r.json()
    assert body["usage"] == {
        "users": 2,
        "source_connections": 2,
        "teams": 1,
        "custom_roles": 1,
        "remote_runners": 1,
    }
