"""Unified event publisher.

Writes events to the durable Redis Streams bus (consumed by background
workers and the correlation engine in later phases) AND fans the
UI-relevant ones out to the existing in-memory SSE EventBus so live
clients see them immediately.

Phase 0: only publish path is wired. Subscribers arrive in Phase 1+.
"""
from __future__ import annotations

import logging

from src.shared.event_bus import Event as SseEvent, EventBus as SseEventBus
from src.shared.event_metrics import (
    record_event_published,
    event_publish_duration_seconds,
)
from src.shared.event_stream import EventStream
from src.shared.event_types.base import Event

logger = logging.getLogger(__name__)

# Event types the UI needs to see live via SSE. Other event types are
# internal-only (workers consume them via Redis Streams; UI doesn't need
# the noise).
_SSE_BRIDGED_TYPES = {
    "code.push", "code.image_push", "code.manual_rescan",
    "scan.started", "scan.progress", "scan.completed", "scan.failed",
    "finding.created", "finding.severity_changed", "finding.closed",
    "chain.created", "chain.updated",
    "intel.cve_published", "intel.exploit_availability_changed",
    "intel.anomaly_detected",
}


class EventPublisher:
    def __init__(self, durable: EventStream, sse_bus: SseEventBus) -> None:
        self._durable = durable
        self._sse_bus = sse_bus

    def publish(self, event: Event) -> None:
        with event_publish_duration_seconds.labels(event_type=event.event_type).time():
            try:
                self._durable.publish(event)
            except Exception:
                logger.exception("Failed to publish event to durable stream: %s", event.event_id)
                raise

            if event.event_type in _SSE_BRIDGED_TYPES:
                self._sse_bus.publish_sync(SseEvent(
                    event_type=event.event_type,
                    data={"event_id": event.event_id, "payload": event.payload},
                    org=event.org_id,
                ))
            record_event_published(event.event_type)


from src.shared.config import load_redis_stream_config
from src.shared.event_bus import get_event_bus

_publisher: EventPublisher | None = None


def get_event_publisher() -> EventPublisher:
    global _publisher
    if _publisher is None:
        cfg = load_redis_stream_config()
        _publisher = EventPublisher(
            durable=EventStream(cfg),
            sse_bus=get_event_bus(),
        )
    return _publisher
