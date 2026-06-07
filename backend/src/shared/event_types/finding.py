"""Finding lifecycle event types."""
from __future__ import annotations

from typing import Literal

from src.shared.event_types.base import Event


class FindingCreatedEvent(Event):
    event_type: Literal["finding.created"] = "finding.created"


class FindingSeverityChangedEvent(Event):
    event_type: Literal["finding.severity_changed"] = "finding.severity_changed"


class FindingMergedEvent(Event):
    event_type: Literal["finding.merged"] = "finding.merged"


class FindingClosedEvent(Event):
    event_type: Literal["finding.closed"] = "finding.closed"
