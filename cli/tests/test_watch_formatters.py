"""Unit tests for `aegis watch` formatters and filters."""

from __future__ import annotations

import json

from aegis_cli.watch_formatters import (
    FINDING_EVENT_TYPES,
    format_json,
    format_pretty,
    matches_filters,
)


def _msg(severity: str = "high", scanner: str = "secrets", finding_id: str = "f-1") -> dict:
    return {
        "event_id": "evt-1",
        "payload": {
            "finding_id": finding_id,
            "severity": severity,
            "scanner_type": scanner,
        },
    }


# ---------------------------------------------------------------------------
# format_pretty
# ---------------------------------------------------------------------------


def test_format_pretty_includes_severity_and_scanner() -> None:
    out = format_pretty("finding.created", _msg("critical", "sast", "f-9"))
    assert "CRITICAL" in out
    assert "sast" in out
    assert "f-9" in out


def test_format_pretty_handles_missing_payload_fields() -> None:
    out = format_pretty("finding.created", {"event_id": "x", "payload": {}})
    # No severity/scanner -- must still render without raising
    assert "CREATED" in out or "created" in out.lower()


def test_format_pretty_handles_unwrapped_payload() -> None:
    out = format_pretty(
        "finding.created",
        {"finding_id": "f-2", "severity": "low", "scanner_type": "dependencies"},
    )
    assert "LOW" in out
    assert "dependencies" in out
    assert "f-2" in out


# ---------------------------------------------------------------------------
# format_json
# ---------------------------------------------------------------------------


def test_format_json_is_single_line_and_parseable() -> None:
    out = format_json("finding.created", _msg("high", "secrets", "f-7"))
    assert "\n" not in out
    parsed = json.loads(out)
    assert parsed["event_type"] == "finding.created"
    assert parsed["severity"] == "high"
    assert parsed["scanner_type"] == "secrets"
    assert parsed["finding_id"] == "f-7"
    assert parsed["event_id"] == "evt-1"
    assert "ts" in parsed


def test_format_json_with_empty_payload() -> None:
    out = format_json("finding.closed", {"event_id": "x", "payload": {}})
    parsed = json.loads(out)
    assert parsed["event_type"] == "finding.closed"
    assert parsed["finding_id"] is None


# ---------------------------------------------------------------------------
# matches_filters
# ---------------------------------------------------------------------------


def test_filter_rejects_non_finding_events() -> None:
    assert not matches_filters(
        "scan.completed",
        _msg(),
        severities=None,
        scanners=None,
        orgs=None,
    )


def test_filter_accepts_all_finding_event_types() -> None:
    for et in FINDING_EVENT_TYPES:
        assert matches_filters(
            et,
            _msg(),
            severities=None,
            scanners=None,
            orgs=None,
        ), et


def test_severity_filter_matches() -> None:
    assert matches_filters(
        "finding.created",
        _msg(severity="high"),
        severities={"high", "critical"},
        scanners=None,
        orgs=None,
    )


def test_severity_filter_rejects() -> None:
    assert not matches_filters(
        "finding.created",
        _msg(severity="low"),
        severities={"high", "critical"},
        scanners=None,
        orgs=None,
    )


def test_scanner_filter_matches() -> None:
    assert matches_filters(
        "finding.created",
        _msg(scanner="secrets"),
        severities=None,
        scanners={"secrets"},
        orgs=None,
    )


def test_scanner_filter_rejects() -> None:
    assert not matches_filters(
        "finding.created",
        _msg(scanner="dependencies"),
        severities=None,
        scanners={"secrets"},
        orgs=None,
    )


def test_org_filter_reads_from_payload() -> None:
    data = {
        "event_id": "x",
        "payload": {
            "finding_id": "f-1",
            "severity": "high",
            "scanner_type": "secrets",
            "org_id": "example-org",
        },
    }
    assert matches_filters(
        "finding.created",
        data,
        severities=None,
        scanners=None,
        orgs={"example-org"},
    )
    assert not matches_filters(
        "finding.created",
        data,
        severities=None,
        scanners=None,
        orgs={"other-org"},
    )


def test_combined_filters_require_all_to_match() -> None:
    msg = _msg(severity="critical", scanner="sast")
    assert matches_filters(
        "finding.created",
        msg,
        severities={"critical"},
        scanners={"sast"},
        orgs=None,
    )
    assert not matches_filters(
        "finding.created",
        msg,
        severities={"critical"},
        scanners={"secrets"},
        orgs=None,
    )
