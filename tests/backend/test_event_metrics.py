"""Tests for event volume + lag metrics."""
from __future__ import annotations


def test_record_event_published_increments_counter():
    from src.shared.event_metrics import (
        events_published_total,
        record_event_published,
    )
    before = events_published_total.labels(event_type="code.push")._value.get()
    record_event_published("code.push")
    after = events_published_total.labels(event_type="code.push")._value.get()
    assert after == before + 1


def test_event_publish_duration_histogram_exists():
    from src.shared.event_metrics import event_publish_duration_seconds
    # Just check the metric exists and is a Histogram
    assert event_publish_duration_seconds is not None
    # Should have the time() context manager
    histo = event_publish_duration_seconds.labels(event_type="code.push")
    assert hasattr(histo, "time")
