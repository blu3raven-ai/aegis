"""Contract tests for the event-emit helpers.

Each helper builds a typed bus event with a specific event_type + payload, and
publishes via _emit which must swallow bus errors so a publish failure never
breaks the caller's path. These tests lock the event type/payload shape that
downstream consumers rely on.
"""
from __future__ import annotations

import pytest

from src.shared import event_emit_helpers as eeh


class _CapturePublisher:
    def __init__(self):
        self.events = []

    def publish(self, event):
        self.events.append(event)


@pytest.fixture
def captured(monkeypatch):
    pub = _CapturePublisher()
    monkeypatch.setattr(eeh, "get_event_publisher", lambda: pub)
    return pub


def test_emit_scan_started(captured):
    eeh.emit_scan_started(scan_id="s1", repo_id="acme/api", scanner_type="sast", trigger_event_id="t1")
    e = captured.events[-1]
    assert e.event_type == "scan.started"
    assert e.source_component == "scan_orchestration"
    assert e.payload == {
        "scan_id": "s1", "repo_id": "acme/api", "scanner_type": "sast", "trigger_event_id": "t1",
    }


def test_emit_scan_completed(captured):
    eeh.emit_scan_completed(scan_id="s1", duration_ms=1234, findings_count=7)
    e = captured.events[-1]
    assert e.event_type == "scan.completed"
    assert e.payload == {"scan_id": "s1", "duration_ms": 1234, "findings_count": 7}


def test_emit_scan_failed_defaults_not_retryable(captured):
    eeh.emit_scan_failed(scan_id="s1", error="boom")
    e = captured.events[-1]
    assert e.event_type == "scan.failed"
    assert e.payload == {"scan_id": "s1", "error": "boom", "retryable": False}


def test_emit_manual_rescan_defaults_not_full(captured):
    eeh.emit_manual_rescan(repo_id="acme/api", scanner_type="sast", source_component="findings_router")
    e = captured.events[-1]
    assert e.event_type == "code.manual_rescan"
    assert e.source_component == "findings_router"
    assert e.payload == {"repo_id": "acme/api", "scanner_type": "sast", "full": False}


def test_emit_finding_created_pulls_id_and_severity(captured):
    eeh.emit_finding_created(
        finding={"id": 42, "severity": "high", "extra": "ignored"},
        scanner_type="sast",
        source_component="code_scanning.scanner",
    )
    e = captured.events[-1]
    assert e.event_type == "finding.created"
    assert e.payload == {"finding_id": 42, "severity": "high", "scanner_type": "sast"}


def test_emit_swallows_publisher_errors(monkeypatch):
    class _Boom:
        def publish(self, _event):
            raise RuntimeError("bus down")

    monkeypatch.setattr(eeh, "get_event_publisher", lambda: _Boom())
    # A bus outage must not propagate to the caller.
    eeh.emit_scan_failed(scan_id="s1", error="x")
    eeh.emit_finding_created(finding={"id": 1, "severity": "low"}, scanner_type="sast", source_component="c")
