"""NotificationEventRouter — event bus consumer that dispatches to destinations.

Subscribes to the durable Redis Streams bus using consumer group
'notification-router'. For every event it:
  1. Loads all enabled destinations for the event's org that match the filter.
  2. Formats the event for the destination type.
  3. Sends via the appropriate sender.
  4. Records the delivery outcome in notification_deliveries.
  5. Emits notification.dispatched or notification.failed.

Runs in a daemon background thread. Starts only when
AEGIS_NOTIFICATIONS_ENABLED=true is set (controlled from main.py lifespan).
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from src.notifications.destination import (
    get_enabled_destinations_for_org,
    record_delivery,
)
from src.notifications.routing import Finding, route_finding
from src.notifications.rules_model import get_active_rules_for_org
from src.notifications.formatter import format_for_email, format_for_slack, format_for_webhook
from src.notifications.senders.email import EmailSender
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender
from src.shared.event_publisher import get_event_publisher
from src.shared.event_stream import EventStream
from src.shared.event_types.notification import (
    NotificationDispatchedEvent,
    NotificationFailedEvent,
)

logger = logging.getLogger(__name__)

_CONSUMER_GROUP = "notification-router"
_CONSUMER_NAME = "notification-router-1"
_BLOCK_MS = 500
_BATCH_SIZE = 50

# Event types the router subscribes to by default.
# Per-destination event_filter can further narrow this list.
SUBSCRIBED_EVENT_TYPES = [
    "chain.created",
    "chain.updated",
    "finding.created",
    "finding.severity_changed",
    "intel.exploit_availability_changed",
    "intel.anomaly_detected",
]

# Severity ordering for min_severity filter comparisons
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_SENDER_MAP = {
    "slack": SlackSender(),
    "webhook": GenericWebhookSender(),
    "email": EmailSender(),
}

_FORMATTER_MAP = {
    "slack": format_for_slack,
    "webhook": format_for_webhook,
    "email": format_for_email,
}


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


def _build_finding_from_event(event: dict[str, Any]) -> Finding:
    """Extract a Finding dataclass from a raw event payload for rule evaluation."""
    payload = event.get("payload", {})
    return Finding(
        severity=(
            payload.get("severity")
            or payload.get("new_severity")
            or "info"
        ),
        scanner=payload.get("scanner") or event.get("event_type", ""),
        repo_id=payload.get("repo_id") or payload.get("repository_id") or "",
        repo_labels=payload.get("repo_labels") or [],
        cve_id=payload.get("cve_id"),
        chain_role=payload.get("chain_role"),
    )


def _resolve_destinations(
    org_id: str,
    event: dict[str, Any],
    all_destinations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply routing rules to narrow the destination list.

    If active rules exist and at least one matches, return only the matched
    channel(s). If no rules match (or org has zero rules), fall back to the
    full event-filter fanout — existing behavior is preserved.
    """
    try:
        rules = get_active_rules_for_org(org_id)
    except Exception:
        logger.warning("could not load routing rules for org %s; falling back", org_id, exc_info=True)
        return [d for d in all_destinations if _event_matches_filter(event, d.get("event_filter"))]

    if not rules:
        # No routing rules configured — legacy fanout
        return [d for d in all_destinations if _event_matches_filter(event, d.get("event_filter"))]

    finding = _build_finding_from_event(event)
    matched_channel_ids = route_finding(finding, rules)

    if not matched_channel_ids:
        # No rule matched — preserve existing behavior
        return [d for d in all_destinations if _event_matches_filter(event, d.get("event_filter"))]

    matched_id_set = set(matched_channel_ids)
    return [d for d in all_destinations if d.get("id") in matched_id_set]


def _dispatch_event(event: dict[str, Any]) -> None:
    """Match destinations and dispatch for a single event."""
    org_id = event.get("org_id", "")
    event_id = event.get("event_id", "")
    event_type = event.get("event_type", "")

    all_destinations = get_enabled_destinations_for_org(org_id)
    destinations = _resolve_destinations(org_id, event, all_destinations)

    for dest in destinations:
        if not _event_matches_filter(event, dest.get("event_filter")):
            continue

        dtype = dest.get("destination_type", "")
        sender = _SENDER_MAP.get(dtype)
        formatter = _FORMATTER_MAP.get(dtype)

        if sender is None or formatter is None:
            logger.warning("no sender/formatter for destination type %r — skipping", dtype)
            continue

        try:
            payload = formatter(event)
            result = sender.send(payload, dest.get("config") or {})
        except Exception as exc:
            logger.exception("unexpected error dispatching to destination %s", dest.get("id"))
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
                payload_summary=_summary_snippet(payload if "payload" in locals() else {}),
                response_code=result_code,
                error=result_err,
            )
        except Exception:
            logger.warning("failed to record delivery for dest %s / event %s", dest.get("id"), event_id, exc_info=True)

        _emit_outcome(event, dest, result_ok, result_err)


def _summary_snippet(payload: dict[str, Any]) -> str:
    summary = payload.get("summary") or payload.get("text") or payload.get("subject") or ""
    return str(summary)[:500]


def _emit_outcome(
    event: dict[str, Any],
    dest: dict[str, Any],
    success: bool,
    error: str | None,
) -> None:
    try:
        publisher = get_event_publisher()
        cls = NotificationDispatchedEvent if success else NotificationFailedEvent
        publisher.publish(
            cls(
                org_id=event.get("org_id", ""),
                source_component="notification-router",
                payload={
                    "source_event_id": event.get("event_id", ""),
                    "source_event_type": event.get("event_type", ""),
                    "destination_id": dest.get("id"),
                    "destination_type": dest.get("destination_type", ""),
                    "error": error,
                },
            )
        )
    except Exception:
        logger.debug("could not emit notification outcome event", exc_info=True)


class NotificationEventRouter:
    """Background thread that polls Redis Streams and dispatches notifications.

    Usage (from main.py lifespan):
        router = NotificationEventRouter(stream_config)
        router.start()
        # ... on shutdown:
        router.stop()
    """

    def __init__(self, stream_config: dict[str, Any]) -> None:
        self._stream = EventStream(stream_config)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="notification-event-router",
            daemon=True,
        )
        self._thread.start()
        logger.info("notification.router: started")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("notification.router: stopped")

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _run_loop(self) -> None:
        import redis as _redis

        while not self._stop_event.is_set():
            for event_type in SUBSCRIBED_EVENT_TYPES:
                if self._stop_event.is_set():
                    break
                try:
                    for raw in self._stream.subscribe(
                        event_type,
                        group=_CONSUMER_GROUP,
                        consumer=_CONSUMER_NAME,
                        block_ms=_BLOCK_MS,
                        count=_BATCH_SIZE,
                    ):
                        if self._stop_event.is_set():
                            break
                        try:
                            _dispatch_event(raw)
                        except Exception:
                            logger.exception(
                                "notification.router: unhandled error dispatching event %s",
                                raw.get("event_id"),
                            )
                        finally:
                            try:
                                self._stream.ack(event_type, _CONSUMER_GROUP, raw["_stream_id"])
                            except Exception:
                                logger.debug("ack failed for stream_id %s", raw.get("_stream_id"))
                except _redis.RedisError:
                    logger.warning("notification.router: Redis error; will retry", exc_info=True)
                except Exception:
                    logger.exception("notification.router: unexpected error in subscribe loop")
