"""Tests for the NotificationEventRouter dispatch logic.

The router's _dispatch_event function is tested synchronously (no Redis
required). Senders and DB writes are mocked.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.notifications.router_event import (
    SUBSCRIBED_EVENT_TYPES,
    _dispatch_event,
    _event_matches_filter,
)

ORG = "acme-org"


def _raw_event(event_type: str = "chain.created", payload: dict | None = None) -> dict:
    return {
        "_stream_id": "1234-0",
        "event_id": "EVT001",
        "event_type": event_type,
        "org_id": ORG,
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": payload or {"severity": "high", "chain_id": "ch-01"},
    }


# ── filter matching ───────────────────────────────────────────────────────────


class TestEventMatchesFilter:
    def test_no_filter_always_matches(self):
        assert _event_matches_filter(_raw_event(), None) is True

    def test_empty_filter_matches(self):
        assert _event_matches_filter(_raw_event(), {}) is True

    def test_event_type_filter_match(self):
        f = {"event_types": ["chain.created"]}
        assert _event_matches_filter(_raw_event("chain.created"), f) is True

    def test_event_type_filter_no_match(self):
        f = {"event_types": ["finding.created"]}
        assert _event_matches_filter(_raw_event("chain.created"), f) is False

    def test_min_severity_critical_passes_critical(self):
        f = {"min_severity": "critical"}
        assert _event_matches_filter(_raw_event(payload={"severity": "critical"}), f) is True

    def test_min_severity_high_blocks_low(self):
        f = {"min_severity": "high"}
        assert _event_matches_filter(_raw_event(payload={"severity": "low"}), f) is False

    def test_min_severity_medium_passes_high(self):
        f = {"min_severity": "medium"}
        assert _event_matches_filter(_raw_event(payload={"severity": "high"}), f) is True

    def test_combined_filter_type_and_severity(self):
        f = {"event_types": ["chain.created"], "min_severity": "high"}
        # Correct type, sufficient severity
        assert _event_matches_filter(_raw_event("chain.created", {"severity": "critical"}), f) is True
        # Correct type, insufficient severity
        assert _event_matches_filter(_raw_event("chain.created", {"severity": "low"}), f) is False
        # Wrong type, sufficient severity
        assert _event_matches_filter(_raw_event("finding.created", {"severity": "critical"}), f) is False


# ── subscribed event types ────────────────────────────────────────────────────


def test_subscribed_event_types_non_empty():
    assert len(SUBSCRIBED_EVENT_TYPES) > 0
    assert "chain.created" in SUBSCRIBED_EVENT_TYPES
    assert "finding.created" in SUBSCRIBED_EVENT_TYPES


# ── dispatch (integration-style with mocks) ───────────────────────────────────


class TestDispatchEvent:
    def _dest(self, dtype: str = "slack", event_filter: dict | None = None) -> dict:
        return {
            "id": 1,
            "org_id": ORG,
            "destination_type": dtype,
            "name": "test-dest",
            "config": {"webhook_url": "https://hooks.example.org/test"},
            "enabled": True,
            "event_filter": event_filter,
        }

    def test_successful_slack_dispatch_records_delivered(self):
        dest = self._dest("slack")
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.response_code = 200
        mock_result.error = None

        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[dest]),
            patch("src.notifications.router_event.record_delivery") as mock_record,
            patch("src.notifications.senders.slack.SlackSender.send", return_value=mock_result),
            patch("src.notifications.router_event._emit_outcome"),
        ):
            _dispatch_event(_raw_event())

        mock_record.assert_called_once()
        call_kwargs = mock_record.call_args.kwargs
        assert call_kwargs["status"] == "delivered"

    def test_failed_send_records_failed(self):
        dest = self._dest("slack")
        mock_result = MagicMock()
        mock_result.success = False
        mock_result.response_code = 500
        mock_result.error = "server error"

        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[dest]),
            patch("src.notifications.router_event.record_delivery") as mock_record,
            patch("src.notifications.senders.slack.SlackSender.send", return_value=mock_result),
            patch("src.notifications.router_event._emit_outcome"),
        ):
            _dispatch_event(_raw_event())

        call_kwargs = mock_record.call_args.kwargs
        assert call_kwargs["status"] == "failed"

    def test_filter_blocks_dispatch(self):
        dest = self._dest("slack", event_filter={"event_types": ["finding.created"]})
        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[dest]),
            patch("src.notifications.router_event.record_delivery") as mock_record,
            patch("src.notifications.senders.slack.SlackSender.send") as mock_send,
        ):
            _dispatch_event(_raw_event("chain.created"))  # not in filter

        mock_send.assert_not_called()
        mock_record.assert_not_called()

    def test_no_destinations_is_noop(self):
        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[]),
            patch("src.notifications.router_event.record_delivery") as mock_record,
        ):
            _dispatch_event(_raw_event())

        mock_record.assert_not_called()

    def test_webhook_dispatch_uses_webhook_sender(self):
        dest = self._dest("webhook")
        dest["config"] = {"url": "https://hooks.example.org/wh", "secret": "s"}
        mock_result = MagicMock()
        mock_result.success = True
        mock_result.response_code = 200
        mock_result.error = None

        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[dest]),
            patch("src.notifications.router_event.record_delivery"),
            patch("src.notifications.senders.webhook.GenericWebhookSender.send", return_value=mock_result) as mock_send,
            patch("src.notifications.router_event._emit_outcome"),
        ):
            _dispatch_event(_raw_event())

        mock_send.assert_called_once()

    def test_unknown_destination_type_skipped_gracefully(self):
        dest = self._dest("fax")  # not a valid sender
        with (
            patch("src.notifications.router_event.get_enabled_destinations_for_org", return_value=[dest]),
            patch("src.notifications.router_event.record_delivery") as mock_record,
        ):
            _dispatch_event(_raw_event())  # should not raise

        mock_record.assert_not_called()
