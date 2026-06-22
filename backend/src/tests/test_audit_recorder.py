"""Unit tests for AuditRecorder.

These tests run without a real database — they mock run_db to verify
that the recorder constructs AuditEvent rows with the correct fields.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.audit_log.recorder import ActorInfo, AuditRecorder, RequestContext


@pytest.fixture
def recorder() -> AuditRecorder:
    return AuditRecorder()


def test_record_persists_event(recorder):
    """record() should call run_db with an AuditEvent carrying all provided fields."""
    captured: list = []

    def fake_run_db(coro_fn):
        # Simulate the async session add by capturing what was added
        session = MagicMock()
        session.add = lambda obj: captured.append(obj)
        import asyncio
        asyncio.run(coro_fn(session))

    with patch("src.audit_log.recorder.run_db", side_effect=fake_run_db):
        recorder.record(
            action="notification.destination.created",
            resource_type="notification_destination",
            resource_id="42",
            actor=ActorInfo(user_id="user-1", username="alice", email="alice@example.com", role="admin"),
            changes={"before": None, "after": {"name": "slack-dev"}},
            metadata={"extra": "info"},
            request=RequestContext(method="POST", path="/api/v1/notifications/destinations", ip="1.2.3.4", user_agent="test-agent", status_code=201),
        )

    assert len(captured) == 1
    evt = captured[0]
    assert evt.action == "notification.destination.created"
    assert evt.resource_type == "notification_destination"
    assert evt.resource_id == "42"
    assert evt.actor_user_id == "user-1"
    assert evt.actor_username == "alice"
    assert evt.actor_email == "alice@example.com"
    assert evt.actor_role == "admin"
    assert evt.changes == {"before": None, "after": {"name": "slack-dev"}}
    assert evt.metadata_json == {"extra": "info"}
    assert evt.request_method == "POST"
    assert evt.request_path == "/api/v1/notifications/destinations"
    assert evt.request_ip == "1.2.3.4"
    assert evt.user_agent == "test-agent"
    assert evt.status_code == 201


def test_record_minimal_args(recorder):
    """record() with only required args should not raise and should set defaults."""
    captured: list = []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.add = lambda obj: captured.append(obj)
        import asyncio
        asyncio.run(coro_fn(session))

    with patch("src.audit_log.recorder.run_db", side_effect=fake_run_db):
        recorder.record(action="test.action", resource_type="test_resource")

    assert len(captured) == 1
    evt = captured[0]
    assert evt.action == "test.action"
    assert evt.resource_type == "test_resource"
    assert evt.actor_user_id is None
    assert evt.changes is None


def test_record_swallows_db_errors(recorder):
    """A DB failure in run_db must not propagate — audit writes are best-effort."""
    with patch("src.audit_log.recorder.run_db", side_effect=RuntimeError("db down")):
        # Should not raise
        recorder.record(action="test.action", resource_type="test_resource")


def test_record_disabled_by_env(recorder, monkeypatch):
    """When AEGIS_AUDIT_LOG_ENABLED=false, record() should be a no-op."""
    monkeypatch.setenv("AEGIS_AUDIT_LOG_ENABLED", "false")
    with patch("src.audit_log.recorder.run_db") as mock_run:
        recorder.record(action="test.action", resource_type="test_resource")
        mock_run.assert_not_called()


def test_record_resource_id_coerced_to_str(recorder):
    """Numeric resource_id must be stored as a string."""
    captured: list = []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.add = lambda obj: captured.append(obj)
        import asyncio
        asyncio.run(coro_fn(session))

    with patch("src.audit_log.recorder.run_db", side_effect=fake_run_db):
        recorder.record(action="test.action", resource_type="t", resource_id=99)

    assert captured[0].resource_id == "99"
