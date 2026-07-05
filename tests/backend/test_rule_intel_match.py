"""Tests for Rule 1: IntelMatchRule — intel.cve_published → SBOM join → findings."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.argus.connector import NullArgusConnector
from src.correlation.rule import RuleContext
from src.correlation.rules.intel_match import IntelMatchRule


ORG = "acme-org"


def _make_ctx(sbom_matches=None, emit=None, state=None):
    if state is None:
        state = MagicMock()
        state.lookup_sboms_containing.return_value = sbom_matches or []
    if emit is None:
        emit = MagicMock()
    return RuleContext(state=state, argus=NullArgusConnector(), emit=emit)


def _make_event(**payload):
    return {
        "_stream_id": "1-0",
        "event_id": "evt-intel-001",
        "event_type": "intel.cve_published",
        "org_id": ORG,
        "source_component": "argus",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {"cve_id": "CVE-2024-0001", "affected_package": "lodash",
                    "affected_version": "4.17.21", "severity": "high",
                    "epss_score": 0.1, **payload},
    }


# ── trigger ───────────────────────────────────────────────────────────────────


def test_intel_match_trigger_is_intel_cve_published():
    rule = IntelMatchRule()
    assert "intel.cve_published" in rule.triggers


# ── no match ──────────────────────────────────────────────────────────────────


def test_no_finding_emitted_when_no_sbom_match():
    ctx = _make_ctx(sbom_matches=[])
    rule = IntelMatchRule()
    rule.evaluate(_make_event(), ctx)
    ctx.emit.emit_finding.assert_not_called()


def test_no_finding_emitted_when_no_package_in_payload():
    ctx = _make_ctx()
    rule = IntelMatchRule()
    event = _make_event()
    del event["payload"]["affected_package"]
    rule.evaluate(event, ctx)
    ctx.emit.emit_finding.assert_not_called()


def test_no_finding_emitted_when_no_cve_id():
    ctx = _make_ctx()
    rule = IntelMatchRule()
    event = _make_event()
    del event["payload"]["cve_id"]
    rule.evaluate(event, ctx)
    ctx.emit.emit_finding.assert_not_called()


# ── single match ──────────────────────────────────────────────────────────────


def test_single_sbom_match_emits_one_finding():
    matches = [{"org": ORG, "repo": "my-repo", "name": "lodash", "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"}]
    ctx = _make_ctx(sbom_matches=matches)
    rule = IntelMatchRule()
    rule.evaluate(_make_event(), ctx)
    ctx.emit.emit_finding.assert_called_once()
    call = ctx.emit.emit_finding.call_args
    finding_data = call.args[0]
    assert finding_data["org"] == ORG
    assert "CVE-2024-0001" in finding_data["identity_key"]
    assert finding_data["severity"] == "high"


def test_multiple_sbom_matches_emit_multiple_findings():
    matches = [
        {"org": ORG, "repo": "repo-a", "name": "lodash", "version": "4.17.21",
         "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"},
        {"org": ORG, "repo": "repo-b", "name": "lodash", "version": "4.17.21",
         "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"},
    ]
    ctx = _make_ctx(sbom_matches=matches)
    rule = IntelMatchRule()
    rule.evaluate(_make_event(), ctx)
    assert ctx.emit.emit_finding.call_count == 2


# ── severity bump ─────────────────────────────────────────────────────────────


def test_high_epss_bumps_severity_to_critical():
    matches = [{"org": ORG, "repo": "repo-a", "name": "lodash", "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"}]
    ctx = _make_ctx(sbom_matches=matches)
    rule = IntelMatchRule()
    # EPSS >= 0.7 should escalate to critical regardless of advisory_severity
    rule.evaluate(_make_event(severity="medium", epss_score=0.9), ctx)
    call = ctx.emit.emit_finding.call_args
    assert call.args[0]["severity"] == "critical"


def test_low_epss_keeps_advisory_severity():
    matches = [{"org": ORG, "repo": "repo-a", "name": "lodash", "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"}]
    ctx = _make_ctx(sbom_matches=matches)
    rule = IntelMatchRule()
    rule.evaluate(_make_event(severity="high", epss_score=0.1), ctx)
    call = ctx.emit.emit_finding.call_args
    assert call.args[0]["severity"] == "high"


# ── provenance ────────────────────────────────────────────────────────────────


def test_finding_identity_key_is_stable():
    """Same CVE + same repo → same identity_key regardless of event_id."""
    matches = [{"org": ORG, "repo": "my-repo", "name": "lodash", "version": "4.17.21",
                "purl": "pkg:npm/lodash@4.17.21", "ecosystem": "npm"}]
    ctx1 = _make_ctx(sbom_matches=matches)
    ctx2 = _make_ctx(sbom_matches=matches)
    rule = IntelMatchRule()

    e1 = _make_event()
    e2 = _make_event()
    e2["event_id"] = "evt-intel-002"

    rule.evaluate(e1, ctx1)
    rule.evaluate(e2, ctx2)

    key1 = ctx1.emit.emit_finding.call_args.args[0]["identity_key"]
    key2 = ctx2.emit.emit_finding.call_args.args[0]["identity_key"]
    assert key1 == key2
