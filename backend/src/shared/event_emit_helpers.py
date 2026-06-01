"""Phase 0 dual-write helpers for the durable event bus.

Every helper here MUST swallow exceptions so that a Redis outage cannot
break an existing scan. Consumers arrive in Phase 1+.
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
    """Phase 0 dual-write — never raises into the caller's path."""
    try:
        get_event_publisher().publish(event)
    except Exception:
        logger.exception("phase0 dual-write failed for %s", event.event_type)


def emit_scan_started(*, org_id: str, scan_id: str, repo_id: str | None,
                      scanner_type: str, trigger_event_id: str,
                      source_component: str = "scan_orchestration") -> None:
    _emit(ScanStartedEvent(
        org_id=org_id,
        source_component=source_component,
        payload={
            "scan_id": scan_id,
            "repo_id": repo_id,
            "scanner_type": scanner_type,
            "trigger_event_id": trigger_event_id,
        },
    ))


def emit_scan_completed(*, org_id: str, scan_id: str, duration_ms: int,
                        findings_count: int,
                        source_component: str = "scan_orchestration") -> None:
    _emit(ScanCompletedEvent(
        org_id=org_id,
        source_component=source_component,
        payload={
            "scan_id": scan_id,
            "duration_ms": duration_ms,
            "findings_count": findings_count,
        },
    ))


def emit_scan_failed(*, org_id: str, scan_id: str, error: str,
                     retryable: bool = False,
                     source_component: str = "scan_orchestration") -> None:
    _emit(ScanFailedEvent(
        org_id=org_id,
        source_component=source_component,
        payload={"scan_id": scan_id, "error": error, "retryable": retryable},
    ))


def emit_manual_rescan(*, org_id: str, repo_id: str | None, scanner_type: str,
                       full: bool = False, source_component: str) -> None:
    _emit(ManualRescanEvent(
        org_id=org_id,
        source_component=source_component,
        payload={
            "repo_id": repo_id,
            "scanner_type": scanner_type,
            "full": full,
        },
    ))


def emit_finding_created(*, org_id: str, finding: dict[str, Any], scanner_type: str,
                         source_component: str) -> None:
    """For Task 19. Defined here to keep all Phase 0 helpers in one place."""
    _emit(FindingCreatedEvent(
        org_id=org_id,
        source_component=source_component,
        payload={
            "finding_id": finding.get("id"),
            "severity": finding.get("severity"),
            "scanner_type": scanner_type,
        },
    ))
