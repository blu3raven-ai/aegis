"""Scan lifecycle event types emitted by the scan orchestrator."""
from __future__ import annotations

from typing import Literal

from src.shared.event_types.base import Event


class ScanStartedEvent(Event):
    event_type: Literal["scan.started"] = "scan.started"


class ScanProgressEvent(Event):
    event_type: Literal["scan.progress"] = "scan.progress"


class ScanFindingEvent(Event):
    event_type: Literal["scan.finding"] = "scan.finding"


class ScanCompletedEvent(Event):
    event_type: Literal["scan.completed"] = "scan.completed"


class ScanFailedEvent(Event):
    event_type: Literal["scan.failed"] = "scan.failed"


class ScanCancelledEvent(Event):
    event_type: Literal["scan.cancelled"] = "scan.cancelled"
