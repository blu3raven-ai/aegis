"""Integration-style tests for audit log.

These tests wire together the real FastAPI app stack (notifications admin router
+ audit middleware + audit recorder) but mock out the database layer — so they
verify the full request-to-audit-record flow without needing a real Postgres.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.audit_log.middleware import AuditMiddleware
from src.audit_log.recorder import AuditRecorder
from src.notifications.admin_router import router as notifications_admin_router


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_integration_app(captured_events: list) -> tuple[FastAPI, TestClient]:
    """Build a minimal app with the real notifications router and audit middleware."""
    class CapturingRecorder(AuditRecorder):
        def record(self, **kwargs):
            captured_events.append(kwargs)

    app = FastAPI()
    app.add_middleware(AuditMiddleware, recorder=CapturingRecorder())
    app.include_router(notifications_admin_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "admin-user"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.tier = None
        request.state.license_claims = None
        return await call_next(request)

    return app, TestClient(app, raise_server_exceptions=False)


# ── tests ─────────────────────────────────────────────────────────────────────


def test_create_destination_produces_audit_event():
    """POSTing a notification destination should generate a notification.destination.created event."""
    events: list = []
    app, client = _make_integration_app(events)

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}), \
         patch("src.notifications.destination.create_destination") as mock_create, \
         patch("src.notifications.admin_router.create_destination") as mock_create2:
        mock_create2.return_value = {"id": 1, "name": "test-slack", "destination_type": "slack"}
        resp = client.post("/api/v1/notifications/destinations", json={
            "org_id": "acme-org",
            "destination_type": "slack",
            "name": "test-slack",
            "config": {"url": "https://hooks.slack.example.com/test"},
        })

    # An audit event must have been captured — either from the decorator or middleware
    assert len(events) >= 1
    actions = [e["action"] for e in events]
    assert "notification.destination.created" in actions


def test_delete_destination_produces_audit_event():
    """DELETing a destination should generate a notification.destination.deleted event."""
    events: list = []
    app, client = _make_integration_app(events)

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}), \
         patch("src.notifications.admin_router.delete_destination", return_value=True):
        resp = client.delete("/api/v1/notifications/destinations/99", params={"org_id": "acme-org"})

    assert len(events) >= 1
    actions = [e["action"] for e in events]
    assert "notification.destination.deleted" in actions


def test_non_admin_route_does_not_audit():
    """A GET request that doesn't match auditable patterns should produce no events."""
    events: list = []
    app, client = _make_integration_app(events)

    with patch("src.settings.router._resolve_effective_permissions", return_value={"manage_settings"}), \
         patch("src.notifications.admin_router.list_destinations", return_value=[]):
        client.get("/api/v1/notifications/destinations", params={"org_id": "acme-org"})

    # GET requests are never auto-audited by the middleware
    middleware_events = [e for e in events if e.get("request") and getattr(e["request"], "method", None) == "GET"]
    assert len(middleware_events) == 0
