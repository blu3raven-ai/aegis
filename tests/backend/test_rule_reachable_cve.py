"""Tests for Rule 2: ReachableCveRule — dep + SAST taint → chain."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.correlation.rule import RuleContext
from src.correlation.rules.reachable_cve import ReachableCveRule


ORG = "acme-org"
REPO = "acme-org/target-repo"


def _make_ctx(open_findings=None, emit=None):
    state = MagicMock()
    state.lookup_open_findings.return_value = open_findings or []
    emit = emit or MagicMock()
    return RuleContext(state=state, argus=None, emit=emit)


def _dep_event(finding_id=1, package="lodash", **extras):
    return {
        "_stream_id": "1-0",
        "event_id": "evt-dep-001",
        "event_type": "scan.finding",
        "org_id": ORG,
        "source_component": "dep_scanner",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "finding": {
                "id": finding_id,
                "tool": "dependencies",
                "org": ORG,
                "repo": REPO,
                "detail": {"package": package, "cve_id": "CVE-2024-1234"},
                **extras,
            }
        },
    }


def _sast_event(finding_id=2, sink_package="lodash", **extras):
    return {
        "_stream_id": "1-1",
        "event_id": "evt-sast-001",
        "event_type": "scan.finding",
        "org_id": ORG,
        "source_component": "sast_scanner",
        "timestamp_utc": "2026-05-31T00:00:00+00:00",
        "payload": {
            "finding": {
                "id": finding_id,
                "tool": "code_scanning",
                "org": ORG,
                "repo": REPO,
                "detail": {"sink_package": sink_package, "rule_id": "sql-injection"},
                **extras,
            }
        },
    }


# ── triggers ──────────────────────────────────────────────────────────────────


def test_reachable_cve_trigger_is_scan_finding():
    rule = ReachableCveRule()
    assert "scan.finding" in rule.triggers


# ── dep-first path ────────────────────────────────────────────────────────────


def test_dep_finding_with_matching_sast_emits_chain():
    sast_findings = [
        {"id": 2, "tool": "code_scanning", "org": ORG, "repo": REPO,
         "state": "open", "severity": "high",
         "detail": {"sink_package": "lodash", "rule_id": "xss"}},
    ]
    ctx = _make_ctx(open_findings=sast_findings)
    ctx.emit.emit_chain.return_value = "chain-001"

    rule = ReachableCveRule()
    rule.evaluate(_dep_event(finding_id=1, package="lodash"), ctx)

    ctx.emit.emit_chain.assert_called_once()
    chain_data = ctx.emit.emit_chain.call_args.args[0]
    assert chain_data["chain_type"] == "reachable_cve"
    assert chain_data["org_id"] == ORG

    ctx.emit.emit_chain_edge.assert_called_once()
    edge_args = ctx.emit.emit_chain_edge.call_args
    assert edge_args.args[0] == "chain-001"  # chain_id
    assert edge_args.args[1] == 1             # dep finding = source
    assert edge_args.args[2] == 2             # sast finding = target


def test_dep_finding_without_matching_sast_no_chain():
    ctx = _make_ctx(open_findings=[])
    rule = ReachableCveRule()
    rule.evaluate(_dep_event(package="lodash"), ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_dep_finding_sast_different_package_no_chain():
    sast_findings = [
        {"id": 5, "tool": "code_scanning", "org": ORG, "repo": REPO,
         "state": "open", "severity": "medium",
         "detail": {"sink_package": "express", "rule_id": "xss"}},
    ]
    ctx = _make_ctx(open_findings=sast_findings)
    rule = ReachableCveRule()
    rule.evaluate(_dep_event(package="lodash"), ctx)
    ctx.emit.emit_chain.assert_not_called()


# ── sast-first path ───────────────────────────────────────────────────────────


def test_sast_finding_with_matching_dep_emits_chain():
    dep_findings = [
        {"id": 10, "tool": "dependencies", "org": ORG, "repo": REPO,
         "state": "open", "severity": "high",
         "detail": {"package": "lodash", "cve_id": "CVE-2024-5678"}},
    ]
    ctx = _make_ctx(open_findings=dep_findings)
    ctx.emit.emit_chain.return_value = "chain-002"

    rule = ReachableCveRule()
    rule.evaluate(_sast_event(finding_id=20, sink_package="lodash"), ctx)

    ctx.emit.emit_chain.assert_called_once()
    ctx.emit.emit_chain_edge.assert_called_once()
    edge_args = ctx.emit.emit_chain_edge.call_args
    assert edge_args.args[1] == 10   # dep finding = source
    assert edge_args.args[2] == 20   # sast finding = target


def test_sast_finding_without_sink_package_no_chain():
    ctx = _make_ctx()
    rule = ReachableCveRule()
    event = _sast_event(finding_id=30)
    event["payload"]["finding"]["detail"].pop("sink_package")
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_sast_finding_non_code_scanning_type_no_chain():
    """Non-SAST tool type should not trigger the SAST path."""
    ctx = _make_ctx()
    rule = ReachableCveRule()
    event = _sast_event(finding_id=40)
    event["payload"]["finding"]["tool"] = "secrets"  # not code_scanning
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()


# ── emit_chain returns None (duplicate suppressed) ────────────────────────────


def test_no_edge_emitted_when_chain_is_duplicate():
    sast_findings = [
        {"id": 50, "tool": "code_scanning", "org": ORG, "repo": REPO,
         "state": "open", "severity": "high",
         "detail": {"sink_package": "lodash"}},
    ]
    ctx = _make_ctx(open_findings=sast_findings)
    ctx.emit.emit_chain.return_value = None  # duplicate suppressed
    rule = ReachableCveRule()
    rule.evaluate(_dep_event(finding_id=60, package="lodash"), ctx)
    ctx.emit.emit_chain_edge.assert_not_called()


# ── missing fields ────────────────────────────────────────────────────────────


def test_event_without_finding_id_is_skipped():
    ctx = _make_ctx()
    rule = ReachableCveRule()
    event = _dep_event()
    event["payload"]["finding"].pop("id")
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()


def test_event_without_repo_is_skipped():
    ctx = _make_ctx()
    rule = ReachableCveRule()
    event = _dep_event()
    event["payload"]["finding"].pop("repo")
    rule.evaluate(event, ctx)
    ctx.emit.emit_chain.assert_not_called()
