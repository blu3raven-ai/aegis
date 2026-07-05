"""Router-layer coverage for the workspace roles endpoints.

Roles carry permission sets, so the read-vs-write permission split is the
security contract: reads need VIEW_ROLES, writes need MANAGE_ROLES. These tests
mock the service and pin the gate on each verb (including that a viewer can read
but not write), the request→service wiring, the camelCase mapping, the
not-found 404, and the GraphQLError→HTTP translation.
"""
from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test"
)

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from graphql import GraphQLError

from src.auth.workspace.roles_router import _role_to_dict, roles_router

_URL = "/api/v1/workspace/roles"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(roles_router)

    @app.middleware("http")
    async def _inject_state(request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.user_org = "acme-org"
        return await call_next(request)

    return app


def _client() -> TestClient:
    return TestClient(_make_app())


def _role(**over):
    base = dict(
        id="role-1", name="Auditor", description="read only",
        permissions=["view_findings"], is_system=False, is_locked=False,
        created_at="2026-01-01T00:00:00.000Z", updated_at="2026-01-02T00:00:00.000Z",
    )
    base.update(over)
    return SimpleNamespace(**base)


def _perm(*allowed):
    """has_role_permission stand-in granting only the listed permissions."""
    return lambda role, role_id, permission: permission in allowed


_PATCH = "src.authz.enforcement.dependencies.has_role_permission"


# ── _role_to_dict (pure) ─────────────────────────────────────────────────────

def test_role_to_dict_maps_camelcase():
    out = _role_to_dict(_role())
    assert out == {
        "id": "role-1", "name": "Auditor", "description": "read only",
        "permissions": ["view_findings"], "isSystem": False, "isLocked": False,
        "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-02T00:00:00.000Z",
    }


# ── read gate (VIEW_ROLES) ───────────────────────────────────────────────────

def test_list_roles_403_without_view():
    with patch(_PATCH, _perm()):
        assert _client().get(_URL).status_code == 403


def test_list_roles_returns_mapped():
    with patch(_PATCH, _perm("view_roles")), \
            patch("src.auth.workspace.roles_router._list_roles", return_value=[_role()]):
        resp = _client().get(_URL)
    assert resp.status_code == 200
    assert resp.json()["roles"][0]["name"] == "Auditor"


def test_get_role_404_when_missing():
    with patch(_PATCH, _perm("view_roles")), \
            patch("src.auth.workspace.roles_router._get_role", return_value=None):
        resp = _client().get(f"{_URL}/nope")
    assert resp.status_code == 404


def test_get_role_200_when_found():
    with patch(_PATCH, _perm("view_roles")), \
            patch("src.auth.workspace.roles_router._get_role", return_value=_role()):
        resp = _client().get(f"{_URL}/role-1")
    assert resp.status_code == 200
    assert resp.json()["role"]["id"] == "role-1"


# ── write gate (MANAGE_ROLES) + viewer cannot write ──────────────────────────

def test_create_role_403_for_viewer():
    # VIEW_ROLES alone must not permit a write.
    with patch(_PATCH, _perm("view_roles")):
        resp = _client().post(_URL, json={"name": "X", "permissions": []})
    assert resp.status_code == 403


def test_create_role_201_and_forwards_input():
    with patch(_PATCH, _perm("manage_roles")), \
            patch("src.auth.workspace.roles_router._create_role", return_value=_role()) as svc:
        resp = _client().post(
            _URL, json={"name": "Auditor", "description": "d", "permissions": ["view_findings"]}
        )
    assert resp.status_code == 201
    assert resp.json()["role"]["name"] == "Auditor"
    payload = svc.call_args.kwargs["input"]
    assert payload.name == "Auditor"
    assert payload.permissions == ["view_findings"]


def test_update_role_403_for_viewer():
    with patch(_PATCH, _perm("view_roles")):
        resp = _client().patch(f"{_URL}/role-1", json={"name": "X", "permissions": []})
    assert resp.status_code == 403


def test_update_role_200():
    with patch(_PATCH, _perm("manage_roles")), \
            patch("src.auth.workspace.roles_router._update_role", return_value=_role()) as svc:
        resp = _client().patch(f"{_URL}/role-1", json={"name": "New", "permissions": []})
    assert resp.status_code == 200
    assert svc.call_args.kwargs["role_id"] == "role-1"


def test_delete_role_403_for_viewer():
    with patch(_PATCH, _perm("view_roles")):
        assert _client().delete(f"{_URL}/role-1").status_code == 403


def test_delete_role_ok_and_forwards_replacement():
    with patch(_PATCH, _perm("manage_roles")), \
            patch("src.auth.workspace.roles_router._delete_role") as svc:
        resp = _client().delete(f"{_URL}/role-1", params={"replacement_role_id": "role-2"})
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert svc.call_args.kwargs["replacement_role_id"] == "role-2"


# ── GraphQLError → HTTP translation ──────────────────────────────────────────

def test_service_conflict_maps_to_409():
    err = GraphQLError("name taken", extensions={"code": "CONFLICT"})
    with patch(_PATCH, _perm("manage_roles")), \
            patch("src.auth.workspace.roles_router._create_role", side_effect=err):
        resp = _client().post(_URL, json={"name": "dup", "permissions": []})
    assert resp.status_code == 409
    assert resp.json()["detail"] == "name taken"
