"""Tests for output formatters."""

from __future__ import annotations

import json

import pytest

from aegis_cli.output import (
    format_findings_table,
    format_findings_json,
    format_decision,
    format_scan_status,
    _extract_severity,
    _extract_package,
    _extract_advisory,
)


_DEP_FINDING = {
    "state": "open",
    "_scanner": "dependencies",
    "repository": {"full_name": "example-org/api"},
    "security_advisory": {
        "severity": "critical",
        "ghsa_id": "GHSA-aaaa",
        "cve_id": "CVE-2023-0001",
    },
    "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}},
    "current_version": "4.17.15",
}

_CODE_FINDING = {
    "state": "open",
    "_scanner": "code_scanning",
    "severity": "high",
    "rule": {"id": "sql-injection", "description": "SQL Injection", "severity": "high"},
    "repository": {"full_name": "example-org/api"},
}


# ---------------------------------------------------------------------------
# format_findings_table
# ---------------------------------------------------------------------------


def test_format_findings_table_empty():
    out = format_findings_table([])
    assert "no findings" in out.lower()


def test_format_findings_table_contains_severity():
    out = format_findings_table([_DEP_FINDING])
    assert "CRITICAL" in out


def test_format_findings_table_contains_package():
    out = format_findings_table([_DEP_FINDING])
    assert "lodash" in out


def test_format_findings_table_multiple_rows():
    out = format_findings_table([_DEP_FINDING, _CODE_FINDING])
    # Both scanner names should appear
    assert "dependencies" in out
    assert "code_scanning" in out


# ---------------------------------------------------------------------------
# format_findings_json
# ---------------------------------------------------------------------------


def test_format_findings_json_is_valid_json():
    out = format_findings_json([_DEP_FINDING])
    parsed = json.loads(out)
    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_format_findings_json_empty_list():
    out = format_findings_json([])
    assert json.loads(out) == []


# ---------------------------------------------------------------------------
# format_decision
# ---------------------------------------------------------------------------


def test_format_decision_allow():
    d = {"decision": "allow", "blockers": [], "rationale": "No issues."}
    out = format_decision(d)
    assert "allow" in out.lower()
    assert "No issues" in out


def test_format_decision_block():
    d = {
        "decision": "block",
        "blockers": [_DEP_FINDING],
        "rationale": "Critical found.",
    }
    out = format_decision(d)
    assert "block" in out.lower()


def test_format_decision_local_source_note():
    d = {"decision": "allow", "blockers": [], "rationale": "ok", "source": "local"}
    out = format_decision(d)
    assert "local" in out.lower()


def test_format_decision_exit_code_mode_suppresses_blockers():
    d = {
        "decision": "block",
        "blockers": [_DEP_FINDING] * 5,
        "rationale": "blocked",
        "source": "local",
    }
    verbose = format_decision(d, exit_code_mode=False)
    terse = format_decision(d, exit_code_mode=True)
    # In exit_code_mode, blocker details should not appear
    assert "lodash" in verbose
    assert "lodash" not in terse


# ---------------------------------------------------------------------------
# format_scan_status
# ---------------------------------------------------------------------------


def test_format_scan_status_shows_run_id():
    run = {
        "id": "run-xyz",
        "org": "example-org",
        "status": "completed",
        "findingsCount": 7,
        "progress": {"percent": 100, "stage": "completed"},
    }
    out = format_scan_status(run)
    assert "run-xyz" in out
    assert "completed" in out.lower()


def test_format_scan_status_shows_error():
    run = {
        "id": "run-fail",
        "org": "example-org",
        "status": "failed",
        "error": "Docker daemon unreachable",
        "progress": {},
    }
    out = format_scan_status(run)
    assert "Docker daemon unreachable" in out


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def test_extract_severity_dependencies():
    assert _extract_severity(_DEP_FINDING) == "critical"


def test_extract_severity_code_scanning():
    assert _extract_severity(_CODE_FINDING) == "high"


def test_extract_severity_fallback_empty():
    assert _extract_severity({}) == ""


def test_extract_package_with_version():
    pkg = _extract_package(_DEP_FINDING)
    assert "lodash" in pkg
    assert "4.17.15" in pkg


def test_extract_package_code_scanning():
    pkg = _extract_package(_CODE_FINDING)
    assert "SQL Injection" in pkg or "sql-injection" in pkg


def test_extract_advisory_cve():
    adv = _extract_advisory(_DEP_FINDING)
    assert adv == "CVE-2023-0001"


def test_extract_advisory_ghsa_fallback():
    finding = dict(_DEP_FINDING)
    finding["security_advisory"] = {"severity": "high", "ghsa_id": "GHSA-bbbb"}
    adv = _extract_advisory(finding)
    assert adv == "GHSA-bbbb"
