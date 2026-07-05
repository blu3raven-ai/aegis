"""Tests for event → payload formatters."""
from __future__ import annotations

import pytest

from src.notifications.formatter import (
    format_for_email,
    format_for_slack,
    format_for_webhook,
)

ORG = "acme-org"


def _event(event_type: str, payload: dict | None = None) -> dict:
    return {
        "event_id": "01HTEST000000000000000001",
        "event_type": event_type,
        "org_id": ORG,
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": payload or {},
    }


# ── Slack ─────────────────────────────────────────────────────────────────────


class TestFormatForSlack:
    def test_chain_created_has_blocks(self):
        result = format_for_slack(_event("chain.created", {"chain_id": "ch-01", "severity": "high"}))
        assert "blocks" in result
        assert "text" in result
        assert isinstance(result["blocks"], list)
        assert len(result["blocks"]) >= 2

    def test_header_block_contains_title(self):
        result = format_for_slack(_event("chain.created", {"chain_id": "ch-01", "severity": "critical"}))
        header = result["blocks"][0]
        assert header["type"] == "header"
        assert "chain" in header["text"]["text"].lower() or "attack" in header["text"]["text"].lower()

    def test_fallback_text_contains_org(self):
        result = format_for_slack(_event("finding.created", {"severity": "high", "title": "CVE-2025-0001"}))
        assert ORG in result["text"]

    def test_severity_emoji_critical(self):
        result = format_for_slack(_event("finding.created", {"severity": "critical"}))
        header_text = result["blocks"][0]["text"]["text"]
        assert ":red_circle:" in header_text

    def test_exploit_availability_changed(self):
        result = format_for_slack(_event(
            "intel.exploit_availability_changed",
            {"cve_id": "CVE-2025-9999", "new_availability": "public-exploit"},
        ))
        assert "CVE-2025-9999" in result["text"]

    def test_anomaly_detected(self):
        result = format_for_slack(_event(
            "intel.anomaly_detected",
            {"scanner_type": "secrets", "multiplier": 5.2, "window_count": 26},
        ))
        assert "secrets" in result["text"] or "anomaly" in result["text"].lower()

    def test_unknown_event_type_does_not_raise(self):
        result = format_for_slack(_event("some.unknown.event", {}))
        assert "blocks" in result


# ── Webhook ───────────────────────────────────────────────────────────────────


class TestFormatForWebhook:
    def test_envelope_keys_present(self):
        result = format_for_webhook(_event("chain.created", {"severity": "high"}))
        assert result["source"] == "aegis"
        assert "event_id" in result
        assert "event_type" in result
        assert "org_id" in result
        assert "payload" in result
        assert "summary" in result

    def test_org_id_preserved(self):
        result = format_for_webhook(_event("finding.created", {"severity": "critical"}))
        assert result["org_id"] == ORG

    def test_payload_forwarded(self):
        payload = {"cve_id": "CVE-2025-1234", "severity": "critical"}
        result = format_for_webhook(_event("finding.created", payload))
        assert result["payload"]["cve_id"] == "CVE-2025-1234"


# ── Email ─────────────────────────────────────────────────────────────────────


class TestFormatForEmail:
    def test_subject_and_body_keys(self):
        result = format_for_email(_event("chain.created", {"severity": "high"}))
        assert "subject" in result
        assert "body" in result

    def test_subject_contains_org(self):
        result = format_for_email(_event("chain.created"))
        assert ORG in result["subject"]

    def test_body_contains_event_id(self):
        result = format_for_email(_event("finding.created", {"severity": "critical"}))
        assert "01HTEST000000000000000001" in result["body"]

    def test_body_contains_severity_field(self):
        result = format_for_email(_event("finding.severity_changed", {"old_severity": "low", "new_severity": "critical"}))
        assert "critical" in result["body"]

    def test_subject_prefix(self):
        result = format_for_email(_event("chain.created"))
        assert result["subject"].startswith("[Aegis]")
