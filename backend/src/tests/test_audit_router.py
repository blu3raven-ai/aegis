"""Unit tests for the audit log query router.

Tests list/filter/pagination against a mocked DB layer so no real Postgres
is needed.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.audit_log.router import router as audit_router
from src.db.models import AuditEvent


def _make_event(
    id_: int,
    action: str = "test.action",
    resource_type: str = "test_resource",
    org_id: str = "acme-org",
) -> AuditEvent:
    evt = AuditEvent()
    evt.id = id_
    evt.action = action
    evt.actor_user_id = "user-1"
    evt.actor_username = "alice"
    evt.actor_email = "alice@example.com"
    evt.actor_role = "admin"
    evt.org_id = org_id
    evt.resource_type = resource_type
    evt.resource_id = str(id_)
    evt.target = None
    evt.request_method = "POST"
    evt.request_path = "/api/v1/test"
    evt.request_ip = "127.0.0.1"
    evt.user_agent = "pytest"
    evt.changes = None
    evt.metadata_json = None
    evt.status_code = 200
    evt.occurred_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    evt.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return evt


def _make_app(events: list) -> FastAPI:
    """Build a minimal FastAPI app with the audit router and a mocked DB."""
    app = FastAPI()
    app.include_router(audit_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        return await call_next(request)

    return app


@pytest.fixture
def mock_rows():
    return [_make_event(1), _make_event(2), _make_event(3)]


def test_list_events_returns_paginated_results(mock_rows):
    app = _make_app(mock_rows)

    def fake_run_db(coro_fn):
        import asyncio
        session = MagicMock()
        # Simulate scalars().all() returning mock_rows
        execute_result = MagicMock()
        execute_result.scalars.return_value.all.return_value = mock_rows

        async def _inner(session):
            return execute_result.scalars().all()

        return asyncio.run(_inner(session))

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}), \
         patch("src.audit_log.router.run_db", side_effect=fake_run_db):
        client = TestClient(app)
        resp = client.get("/api/v1/audit/events?limit=10&offset=0")

    assert resp.status_code == 200
    data = resp.json()
    assert "events" in data
    assert data["limit"] == 10
    assert data["offset"] == 0
    assert len(data["events"]) == 3


def test_list_events_limit_capped_at_500(mock_rows):
    app = _make_app(mock_rows)

    def fake_run_db(coro_fn):
        import asyncio

        async def _inner(session):
            return mock_rows

        session = MagicMock()
        return asyncio.run(_inner(session))

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}), \
         patch("src.audit_log.router.run_db", side_effect=fake_run_db):
        client = TestClient(app)
        resp = client.get("/api/v1/audit/events?limit=9999")

    assert resp.status_code == 200
    assert resp.json()["limit"] == 500


def test_list_events_requires_permission():
    app = _make_app([])

    with patch("src.settings.router._resolve_effective_permissions", return_value=set()):
        client = TestClient(app)
        resp = client.get("/api/v1/audit/events")

    assert resp.status_code == 403


def test_list_events_disabled_env(mock_rows, monkeypatch):
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")
    app = _make_app(mock_rows)

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}):
        client = TestClient(app)
        resp = client.get("/api/v1/audit/events")

    assert resp.status_code == 403
