"""Intel event types published by Argus or other intelligence sources."""
from __future__ import annotations

from typing import Literal

from src.shared.event_types.base import Event


class CvePublishedEvent(Event):
    event_type: Literal["intel.cve_published"] = "intel.cve_published"


class EpssChangedEvent(Event):
    event_type: Literal["intel.epss_changed"] = "intel.epss_changed"


class ExploitAvailabilityChangedEvent(Event):
    event_type: Literal["intel.exploit_availability_changed"] = (
        "intel.exploit_availability_changed"
    )


class RulePackUpdatedEvent(Event):
    event_type: Literal["intel.rule_pack_updated"] = "intel.rule_pack_updated"


class AnomalyDetectedEvent(Event):
    """Emitted by the anomaly_detection temporal rule when finding rate spikes.

    Payload fields:
      - window_count: int — findings seen in the current sliding window
      - baseline: float — trailing-7-day average used as the reference
      - multiplier: float — window_count / baseline (always >= threshold)
      - scanner_type: str
      - severity: str
    """
    event_type: Literal["intel.anomaly_detected"] = "intel.anomaly_detected"
