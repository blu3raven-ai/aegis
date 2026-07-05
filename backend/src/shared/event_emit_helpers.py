"""Helpers for emitting events to the durable bus.

Every helper here swallows exceptions so a bus outage cannot break the
caller's path.
"""
from __future__ import annotations

import logging
from typing import Any

from src.shared.event_publisher import get_event_publisher
from src.shared.event_types.code import ManualRescanEvent
from src.shared.event_types.finding import FindingCreatedEvent
from src.shared.event_types.scan import (
    ScanCompletedEvent,
    ScanFailedEvent,
    ScanStartedEvent,
)

logger = logging.getLogger(__name__)


def _emit(event) -> None:
    try:
        get_event_publisher().publish(event)
    except Exception:
        logger.exception("event emit failed for %s", event.event_type)


def emit_scan_started(*, scan_id: str, repo_id: str | None,
                      scanner_type: str, trigger_event_id: str,
                      source_component: str = "scan_orchestration") -> None:
    _emit(ScanStartedEvent(
        source_component=source_component,
        payload={
            "scan_id": scan_id,
            "repo_id": repo_id,
            "scanner_type": scanner_type,
            "trigger_event_id": trigger_event_id,
        },
    ))


def emit_scan_completed(*, scan_id: str, duration_ms: int,
                        findings_count: int,
                        source_component: str = "scan_orchestration") -> None:
    _emit(ScanCompletedEvent(
        source_component=source_component,
        payload={
            "scan_id": scan_id,
            "duration_ms": duration_ms,
            "findings_count": findings_count,
        },
    ))


def emit_scan_failed(*, scan_id: str, error: str,
                     retryable: bool = False,
                     source_component: str = "scan_orchestration") -> None:
    _emit(ScanFailedEvent(
        source_component=source_component,
        payload={"scan_id": scan_id, "error": error, "retryable": retryable},
    ))


def emit_manual_rescan(*, repo_id: str | None, scanner_type: str,
                       full: bool = False, source_component: str) -> None:
    _emit(ManualRescanEvent(
        source_component=source_component,
        payload={
            "repo_id": repo_id,
            "scanner_type": scanner_type,
            "full": full,
        },
    ))


def emit_finding_created(*, finding: dict[str, Any], scanner_type: str,
                         source_component: str) -> None:
    _emit(FindingCreatedEvent(
        source_component=source_component,
        payload={
            "finding_id": finding.get("id"),
            "severity": finding.get("severity"),
            "scanner_type": scanner_type,
        },
    ))
