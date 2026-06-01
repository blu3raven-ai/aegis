"""Prometheus metrics for the durable event bus.

Phase 0 ships volume counters only. Phase 1 adds consumer lag.
"""
from __future__ import annotations

from prometheus_client import Counter, Histogram

events_published_total = Counter(
    "aegis_events_published_total",
    "Total events published to the durable bus, by event_type.",
    ["event_type"],
)

event_publish_duration_seconds = Histogram(
    "aegis_event_publish_duration_seconds",
    "Time to publish one event (durable + SSE bridge).",
    ["event_type"],
)


def record_event_published(event_type: str) -> None:
    events_published_total.labels(event_type=event_type).inc()
