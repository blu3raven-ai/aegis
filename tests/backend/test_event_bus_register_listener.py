"""Tests for EventBus.register_listener — synchronous callback subscription."""
from __future__ import annotations

from src.shared.event_bus import Event, EventBus


def _ev(event_type: str = "test.evt", data: dict | None = None) -> Event:
    return Event(event_type=event_type, data=data or {})


def test_register_listener_receives_published_events():
    bus = EventBus()
    received: list[Event] = []
    bus.register_listener(received.append)

    bus.publish(_ev("a"))
    bus.publish(_ev("b"))

    assert [e.event_type for e in received] == ["a", "b"]


def test_unregister_listener_stops_delivery():
    bus = EventBus()
    received: list[Event] = []
    token = bus.register_listener(received.append)

    bus.publish(_ev("first"))
    bus.unregister_listener(token)
    bus.publish(_ev("second"))

    assert [e.event_type for e in received] == ["first"]


def test_listener_exception_does_not_break_publish():
    bus = EventBus()
    good_received: list[Event] = []

    def _bad(_evt):
        raise RuntimeError("boom")

    bus.register_listener(_bad)
    bus.register_listener(good_received.append)

    bus.publish(_ev("ok"))

    assert len(good_received) == 1


def test_multiple_listeners_all_receive():
    bus = EventBus()
    a: list[Event] = []
    b: list[Event] = []
    bus.register_listener(a.append)
    bus.register_listener(b.append)

    bus.publish(_ev("x"))

    assert len(a) == 1
    assert len(b) == 1
