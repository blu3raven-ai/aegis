"""Router-layer coverage for the workspace grants endpoints.

Grants are the asset-scope (BOLA) control surface, so the permission gate on
every verb is the security-critical contract. These tests mock the service so
they pin the router layer only: the MANAGE_ORGANISATIONS gate (403 without it),
the request→service argument wiring, the camelCase response mapping, and the
GraphQLError→HTTP translation.
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

from src.auth.workspace.grants_router import _grant_to_dict, grants_router

_URL = "/api/v1/workspace/grants"


def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(grants_router)

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


def _grant(**over):
    base = dict(
        subject_type="user", subject_id="user-9", asset_id="asset-1",
        asset_type="repo", asset_display_name="acme-org/widgets",
        asset_external_ref="github:acme-org/widgets", source="manual",
        created_at="2026-01-01T00:00:00.000Z",
    )
    base.update(over)
    return SimpleNamespace(**base)


# ── _grant_to_dict (pure) ────────────────────────────────────────────────────

def test_grant_to_dict_maps_camelcase():
    out = _grant_to_dict(_grant())
    assert out == {
        "subjectType": "user",
        "subjectId": "user-9",
        "assetId": "asset-1",
        "assetType": "repo",
        "assetDisplayName": "acme-org/widgets",
        "assetExternalRef": "github:acme-org/widgets",
        "source": "manual",
        "createdAt": "2026-01-01T00:00:00.000Z",
    }


# ── permission gate (403) ────────────────────────────────────────────────────

def _deny(*_a, **_k):
    return False


def test_list_grants_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _deny):
        resp = _client().get(_URL)
    assert resp.status_code == 403


def test_add_grant_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _deny):
        resp = _client().post(_URL, json={"subject_type": "user", "subject_id": "u", "asset_id": "a"})
    assert resp.status_code == 403


def test_remove_grant_403_without_permission():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _deny):
        resp = _client().request(
            "DELETE", _URL, json={"subject_type": "user", "subject_id": "u", "asset_id": "a"}
        )
    assert resp.status_code == 403


# ── happy paths (service mocked) ─────────────────────────────────────────────

def _allow(*_a, **_k):
    return True


def test_list_grants_returns_mapped_grants_and_passes_filters():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _allow), \
            patch("src.auth.workspace.grants_router._list_grants", return_value=[_grant()]) as svc:
        resp = _client().get(_URL, params={"subject_type": "user", "asset_id": "asset-1"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["grants"][0]["assetDisplayName"] == "acme-org/widgets"
    # Query filters are forwarded to the service.
    assert svc.call_args.kwargs["subject_type"] == "user"
    assert svc.call_args.kwargs["asset_id"] == "asset-1"


def test_add_grant_201_and_forwards_body():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _allow), \
            patch("src.auth.workspace.grants_router._add_grant") as svc:
        resp = _client().post(
            _URL,
            json={"subject_type": "team", "subject_id": "team-1", "asset_id": "asset-2", "source": "scim"},
        )
    assert resp.status_code == 201
    assert resp.json() == {"ok": True}
    assert svc.call_args.kwargs["subject_id"] == "team-1"
    assert svc.call_args.kwargs["source"] == "scim"


def test_add_grant_source_defaults_to_manual():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _allow), \
            patch("src.auth.workspace.grants_router._add_grant") as svc:
        _client().post(_URL, json={"subject_type": "user", "subject_id": "u", "asset_id": "a"})
    assert svc.call_args.kwargs["source"] == "manual"


def test_remove_grant_ok_and_forwards_body():
    with patch("src.authz.enforcement.dependencies.has_role_permission", _allow), \
            patch("src.auth.workspace.grants_router._remove_grant") as svc:
        resp = _client().request(
            "DELETE", _URL,
            json={"subject_type": "user", "subject_id": "user-9", "asset_id": "asset-1"},
        )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert svc.call_args.kwargs["asset_id"] == "asset-1"


# ── GraphQLError → HTTP translation ──────────────────────────────────────────

def test_service_bad_input_maps_to_400():
    err = GraphQLError("bad subject", extensions={"code": "BAD_USER_INPUT"})
    with patch("src.authz.enforcement.dependencies.has_role_permission", _allow), \
            patch("src.auth.workspace.grants_router._add_grant", side_effect=err):
        resp = _client().post(_URL, json={"subject_type": "x", "subject_id": "y", "asset_id": "z"})
    assert resp.status_code == 400
    assert resp.json()["detail"] == "bad subject"
