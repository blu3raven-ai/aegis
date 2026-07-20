"""Tests for notification destination CRUD, admin router validation paths,
test-send payload construction, and the event router's filter predicate.

Mocks `run_db` so these tests stay in-process: we exercise the business logic
(validation, dict shapes, routing) rather than the asyncpg integration.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from src.authz.enforcement.dependencies import Permission  # noqa: E402
from src.authz.permissions.catalog import MANAGE_SETTINGS  # noqa: E402
from src.notifications import test_send as test_send_mod
from src.settings.notifications.router import config_router as notifications_config_router
from src.notifications.destination import (
    VALID_DEST_TYPES,
    _delivery_to_dict,
    _dest_to_dict,
    create_destination,
    delete_destination,
    list_pending_retries,
    read_config_secret,
    record_delivery,
    update_destination,
)
from src.shared.encryption import is_encrypted
from src.notifications.router_event import (
    SUBSCRIBED_EVENT_TYPES,
    _event_matches_filter,
    _summary_snippet,
)
from src.notifications.test_send import build_test_payload, send_test_payload




def _run_against_fake_session(captured_objects: list, captured_deletes: list | None = None):
    """Return a fake `run_db` that drives the inner coroutine against a fake
    AsyncSession.

    The fake session exposes the methods touched by destination.py: add(),
    flush(), execute(), delete(). execute() returns a stub Result so .scalars()
    and .first() don't blow up — individual tests override execute() to feed
    the scenario they need.
    """
    captured_deletes = captured_deletes if captured_deletes is not None else []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.add = lambda obj: captured_objects.append(obj)

        async def _flush():
            return None

        async def _delete(obj):
            captured_deletes.append(obj)

        session.flush = _flush
        session.delete = _delete
        return asyncio.run(coro_fn(session))

    return fake_run_db, captured_objects, captured_deletes




def test_dest_to_dict_returns_iso_timestamps_and_full_shape():
    now = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    dest = SimpleNamespace(
        id=42,
        destination_type="slack",
        name="ops",
        config={"webhook_url": "https://example.test/x"},
        enabled=True,
        event_filter={"min_severity": "high"},
        created_at=now,
        updated_at=now,
    )

    out = _dest_to_dict(dest)
    assert out["id"] == 42
    assert out["destination_type"] == "slack"
    assert out["name"] == "ops"
    # _dest_to_dict is the internal (send-path) shape — config stays unredacted;
    # redaction happens at the GraphQL read boundary (_dest_to_gql).
    assert out["config"] == {"webhook_url": "https://example.test/x"}
    assert out["enabled"] is True
    assert out["event_filter"] == {"min_severity": "high"}
    assert out["created_at"].startswith("2026-01-02T03:04:05")
    assert out["updated_at"].startswith("2026-01-02T03:04:05")


def test_dest_to_dict_handles_null_timestamps():
    dest = SimpleNamespace(
        id=1,
        destination_type="email",
        name="x",
        config={},
        enabled=False,
        event_filter=None,
        created_at=None,
        updated_at=None,
    )
    out = _dest_to_dict(dest)
    assert out["created_at"] is None
    assert out["updated_at"] is None


def test_delivery_to_dict_iso_timestamp():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    delivery = SimpleNamespace(
        id=9,
        destination_id=1,
        event_id="ev-1",
        event_type="finding.created",
        status="delivered",
        payload_summary="summary",
        response_code=200,
        error=None,
        attempted_at=now,
    )
    out = _delivery_to_dict(delivery)
    assert out["status"] == "delivered"
    assert out["response_code"] == 200
    assert out["attempted_at"].startswith("2026-06-01")




def test_create_destination_rejects_unknown_type_before_db():
    # Fail-loudly: invalid types must never reach the DB layer.
    with patch("src.notifications.destination.run_db") as mock_run_db:
        with pytest.raises(ValueError, match="destination_type"):
            create_destination("jira", "ops", {"x": 1})
    mock_run_db.assert_not_called()


def test_create_destination_persists_model_and_returns_dict_shape():
    fake_run_db, captured, _ = _run_against_fake_session([])

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = create_destination(
            destination_type="slack",
            name="ops-slack",
            config={"webhook_url": "https://hooks.example.test/abc"},
            enabled=True,
            event_filter={"min_severity": "critical"},
        )

    assert len(captured) == 1
    persisted = captured[0]
    assert persisted.destination_type == "slack"
    assert persisted.name == "ops-slack"
    assert persisted.enabled is True
    assert persisted.event_filter == {"min_severity": "critical"}
    assert out["destination_type"] == "slack"
    assert out["name"] == "ops-slack"


@pytest.mark.parametrize("dtype", sorted(VALID_DEST_TYPES))
def test_create_destination_accepts_each_supported_type(dtype):
    # Stream E shrunk VALID_DEST_TYPES to {slack, webhook, email}; lock that.
    fake_run_db, _, _ = _run_against_fake_session([])
    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        create_destination(dtype, name=f"{dtype}-dest", config={})


def test_valid_dest_types_does_not_include_removed_aspirational_channels():
    # Guard against accidental re-introduction of senders deleted in Stream E.
    for removed in ("jira", "linear", "github_issues", "github-issues", "pagerduty"):
        assert removed not in VALID_DEST_TYPES




def _stub_execute_returning_none():
    """An async session.execute() stub whose .scalars().first() yields None."""
    scalars = MagicMock()
    scalars.first = MagicMock(return_value=None)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    async def _execute(_stmt):
        return result

    return _execute


def test_update_destination_returns_none_when_not_found():
    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_none()
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = update_destination(9999, name="renamed")
    assert out is None


def test_delete_destination_returns_false_when_not_found():
    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_none()
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = delete_destination(9999)
    assert out is False




def test_record_delivery_inserts_new_row_when_none_exists():
    captured: list = []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.add = lambda obj: captured.append(obj)
        session.execute = _stub_execute_returning_none()

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = record_delivery(
            destination_id=1,
            event_id="event-abc",
            event_type="finding.created",
            status="delivered",
            response_code=200,
        )

    assert len(captured) == 1
    inserted = captured[0]
    assert inserted.event_id == "event-abc"
    assert inserted.status == "delivered"
    assert out["status"] == "delivered"


def test_record_delivery_updates_existing_row_when_present():
    existing = SimpleNamespace(
        id=7,
        destination_id=1,
        event_id="event-abc",
        event_type="finding.created",
        status="failed",
        payload_summary=None,
        response_code=500,
        error="old",
        attempted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    scalars = MagicMock()
    scalars.first = MagicMock(return_value=existing)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    async def _execute(_stmt):
        return result

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _execute

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    inserted_objs: list = []
    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = record_delivery(
            destination_id=1,
            event_id="event-abc",
            event_type="finding.created",
            status="delivered",
            response_code=200,
        )

    # The pre-existing row must have been mutated, not duplicated.
    assert existing.status == "delivered"
    assert existing.response_code == 200
    assert out["status"] == "delivered"
    assert out["id"] == 7
    assert inserted_objs == []




def test_list_pending_retries_returns_dict_shapes():
    # The retry-worker projection carries just what a re-send needs: the stored
    # payload, attempt count, and the (id, destination_id, event_id, event_type)
    # identity — not the full delivery audit shape.
    row = SimpleNamespace(
        id=1,
        destination_id=7,
        event_id="e1",
        event_type="finding.created",
        attempts=2,
        payload='{"text": "hi"}',
        next_attempt_at=datetime(2026, 5, 1, tzinfo=timezone.utc),
    )
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=[row])
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    async def _execute(_stmt):
        return result

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _execute
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = list_pending_retries(limit=10)

    assert len(out) == 1
    assert out[0]["destination_id"] == 7
    assert out[0]["attempts"] == 2
    assert out[0]["payload"] == '{"text": "hi"}'
    assert out[0]["next_attempt_at"].startswith("2026-05-01")




_MANAGE = {"manage_settings"}


def _admin_app() -> TestClient:
    app = FastAPI()
    app.include_router(notifications_config_router)

    @app.middleware("http")
    async def inject_user(request: Request, call_next):
        request.state.user_sub = "user-1"
        request.state.user_role = "admin"
        request.state.user_role_id = None
        request.state.tier = None
        request.state.license_claims = None
        return await call_next(request)

    app.dependency_overrides[Permission(MANAGE_SETTINGS)] = lambda: None
    return TestClient(app, raise_server_exceptions=False)


def test_admin_create_destination_rejects_unknown_type_with_422():
    client = _admin_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE):
        resp = client.post(
            "/api/v1/notifications/destinations",
            json={"destination_type": "pagerduty", "name": "x", "config": {}},
        )
    assert resp.status_code == 422
    assert "destination_type" in resp.text


def test_admin_create_destination_returns_409_on_duplicate_name():
    client = _admin_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch(
             "src.settings.notifications.router.create_destination",
             side_effect=Exception("duplicate key value violates unique constraint uq_notif_dest_name"),
         ):
        resp = client.post(
            "/api/v1/notifications/destinations",
            json={"destination_type": "slack", "name": "dup", "config": {}},
        )
    assert resp.status_code == 409


def test_admin_update_destination_404_when_missing():
    client = _admin_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch("src.settings.notifications.router.update_destination", return_value=None):
        resp = client.put(
            "/api/v1/notifications/destinations/999",
            json={"name": "renamed"},
        )
    assert resp.status_code == 404


def test_admin_delete_destination_204_on_success():
    client = _admin_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch("src.settings.notifications.router.delete_destination", return_value=True):
        resp = client.delete("/api/v1/notifications/destinations/1")
    assert resp.status_code == 204


def test_admin_delete_destination_404_when_missing():
    client = _admin_app()
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch("src.settings.notifications.router.delete_destination", return_value=False):
        resp = client.delete("/api/v1/notifications/destinations/999")
    assert resp.status_code == 404


def test_admin_test_send_returns_delivered_status_on_success():
    client = _admin_app()
    dest = {"id": 1, "destination_type": "slack", "name": "ops", "config": {}}
    fake_result = SimpleNamespace(success=True, error=None)
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch("src.settings.notifications.router.get_destination", return_value=dest), \
         patch("src.settings.notifications.router.send_test_payload", return_value=fake_result):
        resp = client.post("/api/v1/notifications/destinations/1/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "delivered"
    assert body["channel"] == "slack"


def test_admin_test_send_returns_failed_status_with_error_message():
    client = _admin_app()
    dest = {"id": 1, "destination_type": "webhook", "name": "ops", "config": {}}
    fake_result = SimpleNamespace(success=False, error="HTTP 503")
    with patch("src.authz.enforcement._resolve_effective_permissions", return_value=_MANAGE), \
         patch("src.settings.notifications.router.get_destination", return_value=dest), \
         patch("src.settings.notifications.router.send_test_payload", return_value=fake_result):
        resp = client.post("/api/v1/notifications/destinations/1/test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "failed"
    assert body["error"] == "HTTP 503"




def test_build_test_payload_slack_shape():
    payload = build_test_payload("slack", "ops")
    assert "text" in payload
    assert isinstance(payload["blocks"], list) and payload["blocks"]
    assert any("Aegis test notification" in str(b) for b in payload["blocks"])


def test_build_test_payload_webhook_marks_test_true():
    payload = build_test_payload("webhook", "ci")
    assert payload["test"] is True
    assert payload["source"] == "aegis"
    assert payload["destination_name"] == "ci"


def test_build_test_payload_email_has_subject_and_body():
    payload = build_test_payload("email", "alerts")
    assert payload["subject"].startswith("[Aegis]")
    assert "alerts" in payload["body"]


def test_build_test_payload_unsupported_type_raises():
    with pytest.raises(ValueError, match="unsupported destination_type"):
        build_test_payload("pagerduty", "x")


def test_send_test_payload_unknown_type_returns_failure_result():
    out = send_test_payload("pagerduty", {}, {})
    assert out.success is False
    assert "no sender registered" in (out.error or "")


def test_send_test_payload_dispatches_to_matching_sender(monkeypatch):
    calls: list = []

    class FakeSlack:
        def send(self, payload, config):
            calls.append((payload, config))
            return SimpleNamespace(success=True, error=None, response_code=200)

    # The senders map is consulted at dispatch time — swap the class there.
    monkeypatch.setitem(test_send_mod._SENDER_CLASSES, "slack", FakeSlack)

    payload = {"text": "hi"}
    config = {"webhook_url": "https://example.test"}
    out = send_test_payload("slack", payload, config)

    assert out.success is True
    assert calls == [(payload, config)]




def test_subscribed_event_types_lock_contract():
    # Locks the set of bus topics the router fans out — additions go through
    # a deliberate change here so we don't accidentally dispatch low-value events.
    assert SUBSCRIBED_EVENT_TYPES == frozenset({
        "finding.created",
        "finding.severity_changed",
        "intel.exploit_availability_changed",
        "intel.anomaly_detected",
    })


def test_event_filter_none_matches_everything():
    event = {"event_type": "finding.created", "payload": {"severity": "low"}}
    assert _event_matches_filter(event, None) is True
    assert _event_matches_filter(event, {}) is True


def test_event_filter_event_types_whitelist_blocks_other_types():
    event = {"event_type": "finding.created", "payload": {}}
    assert _event_matches_filter(event, {"event_types": ["finding.severity_changed"]}) is False


def test_event_filter_event_types_whitelist_allows_listed_type():
    event = {"event_type": "finding.created", "payload": {}}
    assert _event_matches_filter(event, {"event_types": ["finding.created"]}) is True


def test_event_filter_min_severity_blocks_lower_severity():
    event = {"event_type": "finding.created", "payload": {"severity": "low"}}
    assert _event_matches_filter(event, {"min_severity": "high"}) is False


def test_event_filter_min_severity_allows_equal_or_higher():
    event = {"event_type": "finding.created", "payload": {"severity": "critical"}}
    assert _event_matches_filter(event, {"min_severity": "high"}) is True
    event2 = {"event_type": "finding.created", "payload": {"severity": "high"}}
    assert _event_matches_filter(event2, {"min_severity": "high"}) is True


def test_event_filter_falls_back_to_new_severity_when_no_severity_field():
    event = {"event_type": "finding.severity_changed", "payload": {"new_severity": "critical"}}
    assert _event_matches_filter(event, {"min_severity": "high"}) is True


def test_event_filter_missing_severity_treated_as_info_and_blocked_by_min():
    event = {"event_type": "finding.created", "payload": {}}
    assert _event_matches_filter(event, {"min_severity": "low"}) is False


def test_summary_snippet_truncates_to_500_chars():
    payload = {"summary": "x" * 1000}
    out = _summary_snippet(payload)
    assert len(out) == 500


def test_summary_snippet_falls_back_to_text_then_subject():
    assert _summary_snippet({"text": "from text"}) == "from text"
    assert _summary_snippet({"subject": "from subject"}) == "from subject"
    assert _summary_snippet({}) == ""




def _stub_execute_returning_scalars(items):
    """An async session.execute() stub whose .scalars().all() yields `items`."""
    scalars = MagicMock()
    scalars.all = MagicMock(return_value=items)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    async def _execute(_stmt):
        return result

    return _execute


def _stub_execute_returning_one(item):
    """An async session.execute() stub whose .scalars().first() yields `item`."""
    scalars = MagicMock()
    scalars.first = MagicMock(return_value=item)
    result = MagicMock()
    result.scalars = MagicMock(return_value=scalars)

    async def _execute(_stmt):
        return result

    return _execute


def test_list_destinations_returns_dict_shapes_in_order():
    from src.notifications.destination import list_destinations

    rows = [
        SimpleNamespace(
            id=1, destination_type="slack", name="ops",
            config={"webhook_url": "https://x"}, enabled=True,
            event_filter=None, created_at=None, updated_at=None,
        ),
        SimpleNamespace(
            id=2, destination_type="email", name="alerts",
            config={"to_addresses": ["a@example.test"]}, enabled=False,
            event_filter={"min_severity": "high"},
            created_at=None, updated_at=None,
        ),
    ]

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_scalars(rows)
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = list_destinations()

    assert [d["id"] for d in out] == [1, 2]
    assert out[0]["destination_type"] == "slack"
    assert out[1]["event_filter"] == {"min_severity": "high"}


def test_get_destination_returns_none_when_not_found():
    from src.notifications.destination import get_destination

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(None)
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = get_destination(9999)
    assert out is None


def test_get_destination_returns_dict_when_found():
    from src.notifications.destination import get_destination

    dest = SimpleNamespace(
        id=7, destination_type="webhook", name="ci",
        config={"url": "https://x"}, enabled=True,
        event_filter=None, created_at=None, updated_at=None,
    )

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(dest)
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = get_destination(7)
    assert out is not None
    assert out["id"] == 7
    assert out["destination_type"] == "webhook"


def test_update_destination_partial_update_only_touches_passed_fields():
    # Caller passes only `name` — config/enabled/event_filter must keep their
    # pre-existing values so a PATCH with one field doesn't blow away the rest.
    from src.notifications.destination import update_destination

    existing = SimpleNamespace(
        id=1, destination_type="slack", name="old",
        config={"webhook_url": "https://x"}, enabled=True,
        event_filter={"min_severity": "high"},
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(existing)

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = update_destination(1, name="renamed")

    assert existing.name == "renamed"
    # Other fields are unchanged
    assert existing.config == {"webhook_url": "https://x"}
    assert existing.enabled is True
    assert existing.event_filter == {"min_severity": "high"}
    assert out is not None
    assert out["name"] == "renamed"


def test_update_destination_can_disable_via_enabled_false():
    # `if enabled is not None` must respect False as a valid value (not
    # treat it like None and skip the update).
    from src.notifications.destination import update_destination

    existing = SimpleNamespace(
        id=1, destination_type="slack", name="x",
        config={}, enabled=True, event_filter=None,
        created_at=None, updated_at=None,
    )

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(existing)

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        update_destination(1, enabled=False)
    assert existing.enabled is False


def test_delete_destination_returns_true_and_calls_session_delete():
    from src.notifications.destination import delete_destination

    existing = SimpleNamespace(
        id=1, destination_type="slack", name="x",
        config={}, enabled=True, event_filter=None,
        created_at=None, updated_at=None,
    )
    deleted: list = []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(existing)

        async def _delete(obj):
            deleted.append(obj)

        session.delete = _delete
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        ok = delete_destination(1)
    assert ok is True
    assert deleted == [existing]


def test_list_deliveries_for_destination_returns_ordered_dicts():
    from src.notifications.destination import list_deliveries_for_destination

    rows = [
        SimpleNamespace(
            id=10, destination_id=1, event_id="e2", event_type="finding.created",
            status="delivered", payload_summary=None, response_code=200, error=None,
            attempted_at=datetime(2026, 6, 2, tzinfo=timezone.utc),
        ),
        SimpleNamespace(
            id=9, destination_id=1, event_id="e1", event_type="finding.created",
            status="failed", payload_summary=None, response_code=500, error="boom",
            attempted_at=datetime(2026, 6, 1, tzinfo=timezone.utc),
        ),
    ]

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_scalars(rows)
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = list_deliveries_for_destination(1, limit=5)

    assert [d["id"] for d in out] == [10, 9]
    assert out[1]["status"] == "failed"
    assert out[1]["error"] == "boom"


def test_get_enabled_destinations_returns_only_enabled_via_filter():
    # The store passes `enabled == True` in the WHERE clause; this test
    # exercises the run_db path and verifies the result shapes flow through.
    from src.notifications.destination import get_enabled_destinations

    enabled = [
        SimpleNamespace(
            id=1, destination_type="slack", name="ops",
            config={}, enabled=True, event_filter=None,
            created_at=None, updated_at=None,
        ),
    ]

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_scalars(enabled)
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = get_enabled_destinations()

    assert len(out) == 1
    assert out[0]["enabled"] is True


def test_record_delivery_propagates_all_optional_fields_on_insert():
    # New row path: payload_summary, response_code, and error must be persisted
    # so the audit dashboard can show why a delivery failed.
    from src.notifications.destination import record_delivery

    captured: list = []

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.add = lambda obj: captured.append(obj)
        session.execute = _stub_execute_returning_one(None)

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        record_delivery(
            destination_id=1,
            event_id="ev-1",
            event_type="finding.created",
            status="failed",
            payload_summary="summary",
            response_code=503,
            error="timeout",
        )

    assert len(captured) == 1
    persisted = captured[0]
    assert persisted.payload_summary == "summary"
    assert persisted.response_code == 503
    assert persisted.error == "timeout"


def test_record_delivery_update_path_overwrites_response_and_error():
    # Existing row path: a retry that succeeds must clear the previous error
    # message so the audit row reflects the final outcome, not the failure
    # that preceded it.
    from src.notifications.destination import record_delivery

    existing = SimpleNamespace(
        id=99, destination_id=1, event_id="ev-1",
        event_type="finding.created", status="failed",
        payload_summary=None, response_code=500, error="old failure",
        attempted_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_one(existing)

        async def _flush():
            return None

        session.flush = _flush
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        record_delivery(
            destination_id=1,
            event_id="ev-1",
            event_type="finding.created",
            status="delivered",
            response_code=200,
            error=None,
        )

    assert existing.status == "delivered"
    assert existing.response_code == 200
    assert existing.error is None


def test_list_pending_retries_empty_returns_empty_list():
    from src.notifications.destination import list_pending_retries

    def fake_run_db(coro_fn):
        session = MagicMock()
        session.execute = _stub_execute_returning_scalars([])
        return asyncio.run(coro_fn(session))

    with patch("src.notifications.destination.run_db", side_effect=fake_run_db):
        out = list_pending_retries()
    assert out == []




# -----------------------------------------------------------------------------
# DB-backed tests: exercise the real CRUD round-trip against Postgres so the
# mock-based pattern above can't silently hide schema drift (this is the same
# class of bug as Finding.repo / v0.4.1 hotfix).
# -----------------------------------------------------------------------------

import pytest_asyncio
from sqlalchemy import delete as sa_delete, select
from uuid import uuid4

from src.db.models import NotificationDelivery, NotificationDestination


@pytest_asyncio.fixture
async def destinations_cleanup(db_session):
    """Track destination IDs created by sync helpers so we can purge them
    plus any cascaded deliveries at teardown."""
    created_ids: list[int] = []
    yield created_ids
    if created_ids:
        await db_session.execute(
            sa_delete(NotificationDelivery).where(
                NotificationDelivery.destination_id.in_(created_ids)
            )
        )
        await db_session.execute(
            sa_delete(NotificationDestination).where(
                NotificationDestination.id.in_(created_ids)
            )
        )
        await db_session.commit()


@pytest.mark.asyncio
async def test_create_destination_persists_model_and_returns_dict_shape_dbbacked(
    db_session, destinations_cleanup,
):
    name = f"ops-slack-{uuid4().hex[:8]}"
    out = create_destination(
        destination_type="slack",
        name=name,
        config={"webhook_url": "https://hooks.example.test/abc"},
        enabled=True,
        event_filter={"min_severity": "critical"},
    )
    destinations_cleanup.append(out["id"])

    assert out["destination_type"] == "slack"
    assert out["name"] == name
    assert out["enabled"] is True
    assert out["event_filter"] == {"min_severity": "critical"}

    result = await db_session.execute(
        select(NotificationDestination).where(NotificationDestination.id == out["id"])
    )
    row = result.scalars().first()
    assert row is not None
    assert row.destination_type == "slack"
    assert row.name == name
    # webhook_url is a bearer secret — stored encrypted, recoverable on read.
    assert is_encrypted(row.config["webhook_url"])
    assert read_config_secret(row.config["webhook_url"]) == "https://hooks.example.test/abc"
    assert row.enabled is True
    assert row.event_filter == {"min_severity": "critical"}


@pytest.mark.asyncio
async def test_create_destination_unique_name_raises_integrity_error_dbbacked(
    db_session, destinations_cleanup,
):
    # `uq_notif_dest_name` is global — a second row with the same name must
    # raise IntegrityError. The 409 mapping in the admin router relies on this.
    from sqlalchemy.exc import IntegrityError

    name = f"dup-{uuid4().hex[:8]}"
    first = create_destination(
        destination_type="slack", name=name, config={"webhook_url": "https://x"},
    )
    destinations_cleanup.append(first["id"])

    with pytest.raises(IntegrityError):
        create_destination(
            destination_type="webhook", name=name, config={"url": "https://y"},
        )


@pytest.mark.asyncio
async def test_update_destination_partial_update_only_touches_passed_fields_dbbacked(
    db_session, destinations_cleanup,
):
    name = f"old-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="slack",
        name=name,
        config={"webhook_url": "https://x"},
        enabled=True,
        event_filter={"min_severity": "high"},
    )
    destinations_cleanup.append(created["id"])

    renamed = f"renamed-{uuid4().hex[:8]}"
    out = update_destination(created["id"], name=renamed)
    assert out is not None
    assert out["name"] == renamed

    # Read-back via db_session: other fields must be untouched.
    result = await db_session.execute(
        select(NotificationDestination).where(NotificationDestination.id == created["id"])
    )
    row = result.scalars().first()
    assert row is not None
    assert row.name == renamed
    assert read_config_secret(row.config["webhook_url"]) == "https://x"
    assert row.enabled is True
    assert row.event_filter == {"min_severity": "high"}


@pytest.mark.asyncio
async def test_update_destination_can_disable_via_enabled_false_dbbacked(
    db_session, destinations_cleanup,
):
    name = f"enabled-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="slack", name=name, config={}, enabled=True,
    )
    destinations_cleanup.append(created["id"])

    update_destination(created["id"], enabled=False)

    result = await db_session.execute(
        select(NotificationDestination).where(NotificationDestination.id == created["id"])
    )
    row = result.scalars().first()
    assert row is not None
    assert row.enabled is False


@pytest.mark.asyncio
async def test_record_delivery_inserts_new_row_when_none_exists_dbbacked(
    db_session, destinations_cleanup,
):
    name = f"deliv-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "https://x"},
    )
    destinations_cleanup.append(created["id"])

    event_id = f"ev-{uuid4().hex[:8]}"
    out = record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="delivered",
        response_code=200,
    )
    assert out["status"] == "delivered"

    result = await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == created["id"],
            NotificationDelivery.event_id == event_id,
        )
    )
    rows = result.scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "delivered"
    assert rows[0].response_code == 200


@pytest.mark.asyncio
async def test_record_delivery_updates_existing_row_when_present_dbbacked(
    db_session, destinations_cleanup,
):
    name = f"deliv-upd-{uuid4().hex[:8]}"
    created = create_destination(
        destination_type="webhook", name=name, config={"url": "https://x"},
    )
    destinations_cleanup.append(created["id"])

    event_id = f"ev-{uuid4().hex[:8]}"
    # First attempt fails.
    record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="failed",
        response_code=500,
        error="boom",
    )
    # Retry succeeds — must MUTATE the existing row, not insert a duplicate
    # (the `uq_notif_delivery_dest_event` constraint enforces this contract).
    out = record_delivery(
        destination_id=created["id"],
        event_id=event_id,
        event_type="finding.created",
        status="delivered",
        response_code=200,
        error=None,
    )
    assert out["status"] == "delivered"

    result = await db_session.execute(
        select(NotificationDelivery).where(
            NotificationDelivery.destination_id == created["id"],
            NotificationDelivery.event_id == event_id,
        )
    )
    rows = result.scalars().all()
    assert len(rows) == 1
    assert rows[0].status == "delivered"
    assert rows[0].response_code == 200
    assert rows[0].error is None
