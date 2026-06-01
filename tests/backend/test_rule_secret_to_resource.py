"""Tests for Rule 3: SecretToResourceRule — verified secret + SSRF/network → chain."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.correlation.rule import RuleContext
from src.correlation.rules.secret_to_resource import SecretToResourceRule, _resource_host


ORG = "acme-org"
RESOURCE_URL = "https://s3.amazonaws.com/private-bucket"


def _make_ctx(open_findings=None, emit=None):
    state = MagicMock()
    state.lookup_open_findings.return_value = open_findings or []
    return RuleContext(state=state, argus=None, emit=emit or MagicMock())


def _secret_event(finding_id=1, target_resource=RESOURCE_URL, verified=True):
    return {
        "_stream_id": "1-0",
        "event_id": "evt-sec-001",
        "event_type": "scan.finding",
        "org_id": ORG,
        "source_component": "secrets_scanner",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "finding": {
                "id": finding_id,
                "tool": "secrets",
                "org": ORG,
                "detail": {
                    "target_resource": target_resource,
                    "verification_status": "verified" if verified else "unverified",
                },
            }
        },
    }


def _sast_ssrf_event(finding_id=2, sink_resource=RESOURCE_URL, rule_id="ssrf"):
    return {
        "_stream_id": "1-1",
        "event_id": "evt-ssrf-001",
        "event_type": "scan.finding",
        "org_id": ORG,
        "source_component": "sast_scanner",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "finding": {
                "id": finding_id,
                "tool": "code_scanning",
                "org": ORG,
                "detail": {
                    "rule_id": rule_id,
                    "sink_resource": sink_resource,
                },
            }
        },
    }


# ── triggers ──────────────────────────────────────────────────────────────────


def test_secret_to_resource_trigger_is_scan_finding():
    rule = SecretToResourceRule()
    assert "scan.finding" in rule.triggers


# ── _resource_host helper ─────────────────────────────────────────────────────


def test_resource_host_extracts_scheme_and_host():
    assert _resource_host("https://s3.amazonaws.com/bucket/key") == "https://s3.amazonaws.com"


def test_resource_host_strips_query_and_fragment():
    assert _resource_host("https://host.example.com/path?q=1#frag") == "https://host.example.com"


def test_resource_host_no_scheme():
    assert _resource_host("host.example.com/path") == "host.example.com"


# ── secret-first path ─────────────────────────────────────────────────────────


def test_verified_secret_with_matching_ssrf_emits_chain():
    ssrf_findings = [
        {"id": 2, "tool": "code_scanning", "org": ORG, "repo": "repo-a", "state": "open",
         "severity": "high", "detail": {
             "rule_id": "ssrf",
             "sink_resource": RESOURCE_URL,
         }},
    ]
    ctx = _make_ctx(open_findings=ssrf_findings)
    ctx.emit.emit_chain.return_value = "chain-sec-001"
    rule = SecretToResourceRule()
    rule.evaluate(_secret_event(finding_id=1), ctx)

    ctx.emit.emit_chain.assert_called_once()
    data = ctx.emit.emit_chain.call_args.args[0]
    assert data["chain_type"] == "data_exfil"
    assert data["severity"] == "critical"
    ctx.emit.emit_chain_edge.assert_called_once()


def test_unverified_secret_no_chain():
    """Unverified secrets must not trigger chains — too noisy."""
    ctx = _make_ctx()
    rule = SecretToResourceRule()
    rule.evaluate(_secret_event(verified=False), ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_secret_without_target_resource_no_chain():
    ctx = _make_ctx()
    rule = SecretToResourceRule()
    event = _secret_event()
    event["payload"]["finding"]["detail"].pop("target_resource")
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_secret_no_matching_ssrf_no_chain():
    ssrf_findings = [
        {"id": 3, "tool": "code_scanning", "org": ORG, "repo": "repo-a", "state": "open",
         "severity": "medium", "detail": {
             "rule_id": "ssrf",
             "sink_resource": "https://other-host.example.com/path",
         }},
    ]
    ctx = _make_ctx(open_findings=ssrf_findings)
    rule = SecretToResourceRule()
    rule.evaluate(_secret_event(), ctx)
    ctx.emit.emit_chain.assert_not_called()


# ── ssrf-first path ───────────────────────────────────────────────────────────


def test_ssrf_finding_with_matching_verified_secret_emits_chain():
    secret_findings = [
        {"id": 10, "tool": "secrets", "org": ORG, "repo": "repo-a", "state": "open",
         "severity": "critical", "detail": {
             "target_resource": RESOURCE_URL,
             "verification_status": "verified",
         }},
    ]
    ctx = _make_ctx(open_findings=secret_findings)
    ctx.emit.emit_chain.return_value = "chain-ssrf-001"
    rule = SecretToResourceRule()
    rule.evaluate(_sast_ssrf_event(finding_id=20), ctx)

    ctx.emit.emit_chain.assert_called_once()
    ctx.emit.emit_chain_edge.assert_called_once()
    edge_args = ctx.emit.emit_chain_edge.call_args
    # Secret is source, SAST is target
    assert edge_args.args[1] == 10
    assert edge_args.args[2] == 20


def test_non_ssrf_rule_id_no_chain():
    ctx = _make_ctx()
    rule = SecretToResourceRule()
    rule.evaluate(_sast_ssrf_event(rule_id="sql-injection"), ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_ssrf_without_sink_resource_no_chain():
    ctx = _make_ctx()
    rule = SecretToResourceRule()
    event = _sast_ssrf_event()
    event["payload"]["finding"]["detail"].pop("sink_resource")
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_unverified_secret_in_lookup_not_matched():
    """When looking from SSRF side, unverified secrets in lookup must not match."""
    secret_findings = [
        {"id": 30, "tool": "secrets", "org": ORG, "repo": "repo-a", "state": "open",
         "severity": "high", "detail": {
             "target_resource": RESOURCE_URL,
             "verification_status": "unverified",  # not verified
         }},
    ]
    ctx = _make_ctx(open_findings=secret_findings)
    rule = SecretToResourceRule()
    rule.evaluate(_sast_ssrf_event(finding_id=40), ctx)
    ctx.emit.emit_chain.assert_not_called()
