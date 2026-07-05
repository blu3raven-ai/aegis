"""Tests for Rule 5: EpssEscalationRule — EPSS crosses threshold → severity bump."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.argus.connector import NullArgusConnector
from src.correlation.rule import RuleContext
from src.correlation.rules.epss_escalation import EpssEscalationRule


ORG = "acme-org"
CVE = "CVE-2024-5555"


def _make_ctx(findings=None, threshold=None, emit=None):
    state = MagicMock()
    state.lookup_findings.return_value = findings or []
    # Return the threshold setting as a string (matches env-var semantics)
    state.get_setting.side_effect = lambda key, default=None: (
        str(threshold) if key == "epss_threshold" and threshold is not None else default
    )
    return RuleContext(state=state, argus=NullArgusConnector(), emit=emit or MagicMock())


def _epss_event(cve_id=CVE, new_epss=0.8, old_epss=0.2):
    return {
        "_stream_id": "1-0",
        "event_id": "evt-epss-001",
        "event_type": "intel.epss_changed",
        "org_id": ORG,
        "source_component": "argus",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {"cve_id": cve_id, "new_epss": new_epss, "old_epss": old_epss},
    }


# ── triggers ──────────────────────────────────────────────────────────────────


def test_epss_escalation_trigger():
    rule = EpssEscalationRule()
    assert "intel.epss_changed" in rule.triggers


# ── threshold crossing ────────────────────────────────────────────────────────


def test_crossing_threshold_bumps_severity():
    findings = [
        {"id": 1, "org": ORG, "severity": "medium", "state": "open",
         "detail": {"cve_id": CVE}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.7)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.8, old_epss=0.2), ctx)

    ctx.emit.emit_severity_change.assert_called_once()
    call = ctx.emit.emit_severity_change.call_args
    assert call.args[0] == 1           # finding_id
    assert call.args[1] == "critical"  # new_severity


def test_already_above_threshold_no_change():
    """EPSS was already above threshold → old_epss >= threshold, no crossing."""
    findings = [
        {"id": 2, "org": ORG, "severity": "high", "state": "open",
         "detail": {"cve_id": CVE}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.7)
    rule = EpssEscalationRule()
    # old already above threshold — not a crossing
    rule.evaluate(_epss_event(new_epss=0.9, old_epss=0.8), ctx)
    ctx.emit.emit_severity_change.assert_not_called()


def test_below_threshold_no_change():
    findings = [
        {"id": 3, "org": ORG, "severity": "medium", "state": "open",
         "detail": {"cve_id": CVE}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.7)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.5, old_epss=0.1), ctx)
    ctx.emit.emit_severity_change.assert_not_called()


# ── multiple findings ─────────────────────────────────────────────────────────


def test_crossing_bumps_all_matching_findings():
    findings = [
        {"id": 10, "org": ORG, "severity": "medium", "state": "open", "detail": {}},
        {"id": 11, "org": ORG, "severity": "low", "state": "open", "detail": {}},
        {"id": 12, "org": ORG, "severity": "high", "state": "open", "detail": {}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.7)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.75, old_epss=0.3), ctx)

    # All three should be bumped (they're below critical)
    assert ctx.emit.emit_severity_change.call_count == 3


def test_already_critical_finding_not_double_bumped():
    """Critical findings should not get severity_change (they're already at top)."""
    findings = [
        {"id": 20, "org": ORG, "severity": "critical", "state": "open", "detail": {}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.7)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.8, old_epss=0.2), ctx)
    ctx.emit.emit_severity_change.assert_not_called()


# ── no findings ───────────────────────────────────────────────────────────────


def test_no_findings_for_cve_is_noop():
    ctx = _make_ctx(findings=[], threshold=0.7)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.9, old_epss=0.1), ctx)
    ctx.emit.emit_severity_change.assert_not_called()


# ── missing cve_id ────────────────────────────────────────────────────────────


def test_event_without_cve_id_is_skipped():
    ctx = _make_ctx()
    rule = EpssEscalationRule()
    event = _epss_event()
    del event["payload"]["cve_id"]
    rule.evaluate(event, ctx)
    ctx.emit.emit_severity_change.assert_not_called()


# ── configurable threshold ────────────────────────────────────────────────────


def test_custom_threshold_honored():
    """Threshold of 0.5 — EPSS 0.6 should trigger."""
    findings = [
        {"id": 30, "org": ORG, "severity": "medium", "state": "open", "detail": {}},
    ]
    ctx = _make_ctx(findings=findings, threshold=0.5)
    rule = EpssEscalationRule()
    rule.evaluate(_epss_event(new_epss=0.6, old_epss=0.4), ctx)
    ctx.emit.emit_severity_change.assert_called_once()
