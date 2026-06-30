"""Contract tests for the rule-based compliance mapper.

map_finding is fed Finding.tool / Finding.severity / Finding.detail by
auto_mapper, so the scanner_type guards must match the *canonical* tool values
(dependencies_scanning, container_scanning, code_scanning, secret_scanning,
iac_scanning). These tests lock each rule and guard against the guards drifting
back to non-canonical strings (which silently produced no mappings).
"""
from __future__ import annotations

from src.compliance.mapper import map_finding


def _ctrls(scanner_type, severity=None, metadata=None):
    return {
        (d.framework, d.control_id)
        for d in map_finding(scanner_type=scanner_type, severity=severity, metadata=metadata)
    }


def test_dependencies_high_impact_maps_vuln_and_monitoring():
    assert _ctrls("dependencies_scanning", "critical") == {
        ("soc2", "CC6.8"), ("iso27001", "A.8.8"), ("pci-dss", "6.3.3"),
        ("pci-dss", "6.3.1"), ("soc2", "CC7.1"), ("soc2", "CC7.2"),
    }


def test_dependencies_low_severity_only_monitoring():
    # Rule 1 (vuln) is high-impact only; Rule 2 (monitoring) fires at any severity.
    assert _ctrls("dependencies_scanning", "low") == {("soc2", "CC7.1")}


def test_container_high_impact_matches_dependencies():
    assert _ctrls("container_scanning", "critical") == {
        ("soc2", "CC6.8"), ("iso27001", "A.8.8"), ("pci-dss", "6.3.3"),
        ("pci-dss", "6.3.1"), ("soc2", "CC7.1"), ("soc2", "CC7.2"),
    }


def test_secrets_map_access_and_crypto_controls():
    assert _ctrls("secret_scanning", "medium") == {
        ("soc2", "CC6.1"), ("iso27001", "A.9.4"), ("pci-dss", "8.3.6"),
    }


def test_sast_sensitive_data():
    assert _ctrls("code_scanning", "medium", {"handles_sensitive_data": True}) == {
        ("soc2", "CC6.7"), ("pci-dss", "6.2.4"),
    }


def test_sast_without_sensitive_flag_maps_nothing():
    assert _ctrls("code_scanning", "low", {}) == set()


def test_iac_base_and_escalation():
    assert _ctrls("iac_scanning", "medium") == {("iso27001", "A.8.9"), ("soc2", "CC6.6")}
    # High severity adds the cloud-config-weakness control + incident-response.
    assert _ctrls("iac_scanning", "high") == {
        ("iso27001", "A.8.9"), ("soc2", "CC6.6"), ("iso27001", "A.5.23"), ("soc2", "CC7.2"),
    }


def test_public_facing_dedup_keeps_single_cc66():
    # Rule 5 and Rule 6 both emit soc2/CC6.6 — the dedup must collapse them.
    drafts = map_finding(
        scanner_type="iac_scanning", severity="medium", metadata={"is_public_facing": True}
    )
    cc66 = [d for d in drafts if (d.framework, d.control_id) == ("soc2", "CC6.6")]
    assert len(cc66) == 1
    assert ("iso27001", "A.5.23") in {(d.framework, d.control_id) for d in drafts}  # public-facing escalation


def test_non_canonical_tool_names_do_not_fire_scanner_rules():
    # Regression guard: the scanner_type guards require canonical Finding.tool
    # values. A non-canonical string yields only severity-based mappings.
    assert _ctrls("dependencies", "critical") == {("soc2", "CC7.2")}  # Rule 7 only
    assert _ctrls("iac", "medium") == set()
    assert _ctrls("containers", "low") == set()
