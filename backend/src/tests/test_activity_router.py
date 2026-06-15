"""Unit tests for the activity feed router.

Tests endpoint shape, query params, cursor pagination, and the /types route.
Uses a mocked DB layer so no real Postgres is required.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.activity.router import router as activity_router  # noqa: E402
from src.activity.service import ActivityEvent, ActivityService  # noqa: E402


_VIEWER_PERMS = {"view_findings"}


# ── App fixture ───────────────────────────────────────────────────────────────

def _make_app() -> FastAPI:
    app = FastAPI()
    app.include_router(activity_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_org = "acme-org"
        return await call_next(request)

    return app


async def _resolve_assets(_request):
    return ["asset-1", "asset-2"]


async def _resolve_no_assets(_request):
    return []


@pytest.fixture
def client():
    return TestClient(_make_app())


@pytest.fixture(autouse=True)
def _default_perms_and_assets():
    """Default-permit + populated asset_ids for every test — override inside test for the negative cases."""
    with (
        patch("src.settings.router._resolve_effective_permissions", return_value=_VIEWER_PERMS),
        patch("src.activity.router.resolve_asset_ids_from_request", side_effect=_resolve_assets),
    ):
        yield


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_event(id_: str = "fe-1", evt_type: str = "finding.created") -> ActivityEvent:
    return ActivityEvent(
        id=id_,
        type=evt_type,
        occurred_at=datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc),
        actor="alice@example.com",
        repo_id="acme-org/api",
        summary="New finding: CVE-2024-12345 in api",
        payload={"finding_id": 42, "tool": "dependencies", "severity": "high"},
    )


# ── /api/v1/activity/types ────────────────────────────────────────────────────

def test_types_endpoint_returns_list(client):
    resp = client.get("/api/v1/activity/types")
    assert resp.status_code == 200
    data = resp.json()
    assert "types" in data
    assert isinstance(data["types"], list)
    assert "finding.created" in data["types"]
    assert "scan.completed" in data["types"]
    assert "integration.connected" in data["types"]


# ── GET /api/v1/activity ──────────────────────────────────────────────────────

def test_list_activity_returns_events(client):
    events = [_make_event("fe-1"), _make_event("fe-2", "scan.completed")]
    with patch.object(ActivityService, "list_recent", return_value=(events, None)):
        resp = client.get("/api/v1/activity")

    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert len(data["events"]) == 2
    assert data["next_cursor"] is None


def test_list_activity_event_shape(client):
    event = _make_event()
    with patch.object(ActivityService, "list_recent", return_value=([event], None)):
        resp = client.get("/api/v1/activity")

    data = resp.json()
    e = data["events"][0]
    assert e["id"] == "fe-1"
    assert e["type"] == "finding.created"
    assert e["occurred_at"] == "2026-01-15T12:00:00+00:00"
    assert e["actor"] == "alice@example.com"
    assert e["repo_id"] == "acme-org/api"
    assert "summary" in e
    assert "payload" in e


def test_list_activity_scopes_to_caller_assets(client):
    """The router must resolve viewer asset_ids and pass them to the service."""
    captured: dict = {}

    def _mock_list(*, asset_ids, **kwargs):
        captured["asset_ids"] = asset_ids
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity")

    assert captured["asset_ids"] == ["asset-1", "asset-2"]


def test_list_activity_ignores_legacy_org_id_query_param(client):
    """Legacy ?org_id=... param must not influence scoping — it's silently dropped."""
    captured: dict = {}

    def _mock_list(*, asset_ids, **kwargs):
        captured["asset_ids"] = asset_ids
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?org_id=other-org")

    assert captured["asset_ids"] == ["asset-1", "asset-2"]


def test_list_activity_empty_assets_returns_empty(client):
    """Viewer with no team access (empty asset_ids) sees no events — fail-closed.

    The fallback to org_id="default" that used to exist in the router has been
    removed; viewers without team access now get an empty feed instead of
    seeing a magic-string org's data.
    """
    captured: dict = {}

    def _mock_list(*, asset_ids, **kwargs):
        captured["asset_ids"] = asset_ids
        return [], None

    with (
        patch("src.activity.router.resolve_asset_ids_from_request", side_effect=_resolve_no_assets),
        patch.object(ActivityService, "list_recent", side_effect=_mock_list),
    ):
        resp = client.get("/api/v1/activity")

    assert resp.status_code == 200
    assert captured["asset_ids"] == []
    assert resp.json()["events"] == []


def test_list_activity_requires_permission(client):
    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        resp = client.get("/api/v1/activity")
    assert resp.status_code == 403


def test_list_activity_with_cursor(client):
    captured: dict = {}

    def _mock_list(*, cursor=None, **kwargs):
        captured["cursor"] = cursor
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?cursor=abc123")

    assert captured["cursor"] == "abc123"


def test_list_activity_with_types_filter(client):
    captured: dict = {}

    def _mock_list(*, types=None, **kwargs):
        captured["types"] = types
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?types=finding.created,scan.completed")

    assert captured["types"] == ["finding.created", "scan.completed"]


def test_list_activity_with_repo_id_filter(client):
    captured: dict = {}

    def _mock_list(*, repo_id=None, **kwargs):
        captured["repo_id"] = repo_id
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?repo_id=acme-org/api")

    assert captured["repo_id"] == "acme-org/api"


def test_list_activity_returns_next_cursor_when_more(client):
    events = [_make_event(f"fe-{i}") for i in range(5)]
    fake_cursor = "eyJ0IjogIjIwMjYtMDEtMTVUMTI6MDA6MDArMDA6MDAiLCAiaSI6ICI1IiwgInMiOiAiYWN0aXZpdHkifQ=="

    with patch.object(ActivityService, "list_recent", return_value=(events, fake_cursor)):
        resp = client.get("/api/v1/activity?limit=5")

    data = resp.json()
    assert data["next_cursor"] == fake_cursor


def test_list_activity_empty(client):
    with patch.object(ActivityService, "list_recent", return_value=([], None)):
        resp = client.get("/api/v1/activity")

    assert resp.status_code == 200
    data = resp.json()
    assert data["events"] == []
    assert data["next_cursor"] is None


def test_list_activity_limit_param(client):
    captured: dict = {}

    def _mock_list(*, limit=50, **kwargs):
        captured["limit"] = limit
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?limit=25")

    assert captured["limit"] == 25


def test_list_activity_since_until_params(client):
    captured: dict = {}

    def _mock_list(*, since=None, until=None, **kwargs):
        captured["since"] = since
        captured["until"] = until
        return [], None

    with patch.object(ActivityService, "list_recent", side_effect=_mock_list):
        client.get("/api/v1/activity?since=2026-01-01T00:00:00Z&until=2026-01-31T23:59:59Z")

    assert captured["since"] is not None
    assert captured["until"] is not None
