"""Event types emitted by the notification dispatch system."""
from __future__ import annotations

from typing import Literal

from src.shared.event_types.base import Event


class NotificationDispatchedEvent(Event):
    event_type: Literal["notification.dispatched"] = "notification.dispatched"


class NotificationFailedEvent(Event):
    event_type: Literal["notification.failed"] = "notification.failed"
