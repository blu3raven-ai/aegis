"""Unified event publisher — fans events to the in-process EventBus."""
from __future__ import annotations

import logging

from src.shared.event_bus import Event as SseEvent, EventBus, get_event_bus
from src.shared.event_metrics import (
    event_publish_duration_seconds,
    record_event_published,
)
from src.shared.event_types.base import Event

logger = logging.getLogger(__name__)


class EventPublisher:
    def __init__(self, sse_bus: EventBus) -> None:
        self._sse_bus = sse_bus

    def publish(self, event: Event) -> None:
        # Fan event out to EventBus — triggers both SSE subscribers and
        # registered listeners (e.g. NotificationEventRouter).
        with event_publish_duration_seconds.labels(event_type=event.event_type).time():
            self._sse_bus.publish_sync(SseEvent(
                event_type=event.event_type,
                data={"event_id": event.event_id, "payload": event.payload},
                org=event.org_id,
            ))
            record_event_published(event.event_type)


_publisher: EventPublisher | None = None


def get_event_publisher() -> EventPublisher:
    global _publisher
    if _publisher is None:
        _publisher = EventPublisher(sse_bus=get_event_bus())
    return _publisher
