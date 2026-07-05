"""Tests for NotificationEventRouter — EventBus-listener model."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

from src.notifications.router_event import NotificationEventRouter
from src.shared.event_bus import Event, EventBus


def _bus() -> EventBus:
    return EventBus()


def test_router_subscribes_to_event_bus_on_start():
    bus = _bus()
    router = NotificationEventRouter(event_bus=bus)
    with patch.object(router, "_handle_event") as handler:
        router.start()
        bus.publish(Event(event_type="finding.created", data={"finding_id": "f1"}))
    handler.assert_called_once()


def test_router_unregisters_on_stop():
    bus = _bus()
    router = NotificationEventRouter(event_bus=bus)
    with patch.object(router, "_handle_event") as handler:
        router.start()
        router.stop()
        bus.publish(Event(event_type="finding.created", data={"finding_id": "f1"}))
    handler.assert_not_called()


def test_router_handler_errors_are_swallowed():
    bus = _bus()
    router = NotificationEventRouter(event_bus=bus)
    with patch.object(router, "_handle_event", side_effect=RuntimeError("boom")):
        router.start()
        bus.publish(Event(event_type="finding.created", data={"finding_id": "f1"}))
