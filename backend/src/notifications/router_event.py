"""NotificationEventRouter — EventBus listener that dispatches to destinations.

Subscribes to the in-process EventBus via register_listener. For every event it:
  1. Loads all enabled destinations for the event's org that match the filter.
  2. Formats the event for the destination type.
  3. Sends via the appropriate sender.
  4. Records the delivery outcome in notification_deliveries.
  5. Emits notification.dispatched or notification.failed.

Starts only when AEGIS_NOTIFICATIONS_ENABLED=true is set (controlled from
main.py lifespan).
"""
from __future__ import annotations

import logging
from typing import Any

from src.shared.event_bus import Event, EventBus, get_event_bus

logger = logging.getLogger(__name__)

# Event types the router subscribes to.
# Per-destination event_filter can further narrow this list.
SUBSCRIBED_EVENT_TYPES = frozenset([
    "finding.created",
    "finding.severity_changed",
    "intel.exploit_availability_changed",
    "intel.anomaly_detected",
])

# Severity ordering for min_severity filter comparisons
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _event_matches_filter(event: dict[str, Any], event_filter: dict[str, Any] | None) -> bool:
    """Return True if the event should be delivered to a destination with this filter."""
    if not event_filter:
        return True

    et = event.get("event_type", "")
    allowed_types: list[str] | None = event_filter.get("event_types")
    if allowed_types and et not in allowed_types:
        return False

    min_sev: str | None = event_filter.get("min_severity")
    if min_sev:
        payload = event.get("payload", {})
        event_sev = (
            payload.get("severity")
            or payload.get("new_severity")
            or "info"
        )
        if _SEVERITY_RANK.get(event_sev, 0) < _SEVERITY_RANK.get(min_sev, 0):
            return False

    return True


def _summary_snippet(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or payload.get("text") or payload.get("subject") or ""
    return str(summary)[:500]


class NotificationEventRouter:
    """EventBus listener that dispatches notifications when events are published.

    Usage (from main.py lifespan):
        router = NotificationEventRouter()
        router.start()
        # ... on shutdown:
        router.stop()
    """

    def __init__(self, event_bus: EventBus | None = None) -> None:
        self._bus = event_bus or get_event_bus()
        self._listener_token: int | None = None

    def start(self) -> None:
        if self._listener_token is not None:
            return
        self._listener_token = self._bus.register_listener(self._on_event)
        logger.info("NotificationEventRouter started — subscribed to event bus")

    def stop(self) -> None:
        if self._listener_token is not None:
            self._bus.unregister_listener(self._listener_token)
            self._listener_token = None
            logger.info("NotificationEventRouter stopped")

    def _on_event(self, event: Event) -> None:
        if event.event_type not in SUBSCRIBED_EVENT_TYPES:
            return
        try:
            self._handle_event(event)
        except Exception:
            logger.exception(
                "NotificationEventRouter dispatch failed for %s", event.event_type
            )

    def _handle_event(self, event: Event) -> None:
        """Dispatch a single event to all matching destinations.

        Imports are deferred to avoid hard dependencies at module load time.
        The dispatch logic dispatches to per-channel senders.
        """
        # Deferred imports — these modules are part of the notifications subsystem
        # and may not exist in all environments.
        from src.notifications.destination import (  # type: ignore[import]
            get_enabled_destinations,
            record_delivery,
        )
        from src.notifications.routing import Finding, route_finding  # type: ignore[import]
        from src.notifications.rules_model import get_active_rules  # type: ignore[import]
        from src.notifications.formatter import (  # type: ignore[import]
            format_for_email,
            format_for_slack,
            format_for_webhook,
        )
        from src.notifications.senders.email import EmailSender  # type: ignore[import]
        from src.notifications.senders.slack import SlackSender  # type: ignore[import]
        from src.notifications.senders.webhook import GenericWebhookSender  # type: ignore[import]
        from src.shared.event_publisher import get_event_publisher
        from src.shared.event_types.notification import (  # type: ignore[import]
            NotificationDispatchedEvent,
            NotificationFailedEvent,
        )

        sender_map = {
            "slack": SlackSender(),
            "webhook": GenericWebhookSender(),
            "email": EmailSender(),
        }
        formatter_map = {
            "slack": format_for_slack,
            "webhook": format_for_webhook,
            "email": format_for_email,
        }

        # Convert Event to the dict shape the helper functions expect
        raw: dict[str, Any] = {
            "event_type": event.event_type,
            "event_id": event.data.get("event_id", ""),
            "payload": event.data,
        }

        event_id = raw["event_id"]
        event_type = raw["event_type"]

        all_destinations = get_enabled_destinations()

        # Apply routing rules to narrow destination list
        try:
            rules = get_active_rules()
        except Exception:
            logger.warning(
                "could not load routing rules; falling back", exc_info=True
            )
            rules = []

        if rules:
            payload_data = raw.get("payload", {})
            finding = Finding(
                severity=(
                    payload_data.get("severity")
                    or payload_data.get("new_severity")
                    or "info"
                ),
                scanner=payload_data.get("scanner") or event_type,
                repo_id=payload_data.get("repo_id") or payload_data.get("repository_id") or "",
                repo_labels=payload_data.get("repo_labels") or [],
                cve_id=payload_data.get("cve_id"),
                chain_role=payload_data.get("chain_role"),
            )
            matched_channel_ids = route_finding(finding, rules)
            if matched_channel_ids:
                matched_id_set = set(matched_channel_ids)
                destinations = [d for d in all_destinations if d.get("id") in matched_id_set]
            else:
                # No rule matched — fall back to event-filter fanout
                destinations = [
                    d for d in all_destinations
                    if _event_matches_filter(raw, d.get("event_filter"))
                ]
        else:
            # No routing rules configured — legacy fanout
            destinations = [
                d for d in all_destinations
                if _event_matches_filter(raw, d.get("event_filter"))
            ]

        for dest in destinations:
            if not _event_matches_filter(raw, dest.get("event_filter")):
                continue

            dtype = dest.get("destination_type", "")
            sender = sender_map.get(dtype)
            formatter = formatter_map.get(dtype)

            if sender is None or formatter is None:
                logger.warning(
                    "no sender/formatter for destination type %r — skipping", dtype
                )
                continue

            formatted_payload: dict[str, Any] = {}
            try:
                formatted_payload = formatter(raw)
                result = sender.send(formatted_payload, dest.get("config") or {})
            except Exception as exc:
                logger.exception(
                    "unexpected error dispatching to destination %s", dest.get("id")
                )
                result_ok = False
                result_code = None
                result_err = str(exc)[:500]
            else:
                result_ok = result.success
                result_code = result.response_code
                result_err = result.error

            status = "delivered" if result_ok else "failed"

            try:
                record_delivery(
                    destination_id=dest["id"],
                    event_id=event_id,
                    event_type=event_type,
                    status=status,
                    payload_summary=_summary_snippet(formatted_payload),
                    response_code=result_code,
                    error=result_err,
                )
            except Exception:
                logger.warning(
                    "failed to record delivery for dest %s / event %s",
                    dest.get("id"),
                    event_id,
                    exc_info=True,
                )

            try:
                publisher = get_event_publisher()
                cls = NotificationDispatchedEvent if result_ok else NotificationFailedEvent
                publisher.publish(
                    cls(
                        org_id="",
                        source_component="notification-router",
                        payload={
                            "source_event_id": event_id,
                            "source_event_type": event_type,
                            "destination_id": dest.get("id"),
                            "destination_type": dtype,
                            "error": result_err,
                        },
                    )
                )
            except Exception:
                logger.debug("could not emit notification outcome event", exc_info=True)
