"""Unit tests for the rule-based compliance mapper."""
from __future__ import annotations

from src.compliance.mapper import map_finding, map_chain, _MappingDraft


def _index(drafts: list[_MappingDraft]) -> dict[tuple[str, str], _MappingDraft]:
    return {(d.framework, d.control_id): d for d in drafts}


def _assert_contains(drafts: list[_MappingDraft], framework: str, control_id: str) -> _MappingDraft:
    idx = _index(drafts)
    key = (framework, control_id)
    assert key in idx, f"Expected ({framework}, {control_id}); got {list(idx)}"
    return idx[key]


def _assert_not_contains(drafts: list[_MappingDraft], framework: str, control_id: str) -> None:
    idx = _index(drafts)
    assert (framework, control_id) not in idx, f"Did NOT expect ({framework}, {control_id})"


def _assert_confidence_valid(drafts: list[_MappingDraft]) -> None:
    for d in drafts:
        assert 0.0 <= d.confidence <= 1.0, f"Confidence {d.confidence} out of range"


# Rule 1: vulnerable components

def test_dep_critical_maps_cc6_8():
    m = _assert_contains(map_finding(scanner_type="dependencies_scanning", severity="critical", metadata={}), "soc2", "CC6.8")
    assert m.confidence >= 0.85


def test_dep_critical_maps_a8_8():
    _assert_contains(map_finding(scanner_type="dependencies_scanning", severity="critical", metadata={}), "iso27001", "A.8.8")


def test_dep_critical_maps_pci_6_3_3():
    m = _assert_contains(map_finding(scanner_type="dependencies_scanning", severity="critical", metadata={}), "pci-dss", "6.3.3")
    assert m.confidence >= 0.8


def test_container_high_maps_three_frameworks():
    drafts = map_finding(scanner_type="containers", severity="high", metadata={})
    _assert_contains(drafts, "soc2", "CC6.8")
    _assert_contains(drafts, "iso27001", "A.8.8")
    _assert_contains(drafts, "pci-dss", "6.3.3")


def test_dep_low_does_not_map_cc6_8():
    drafts = map_finding(scanner_type="dependencies_scanning", severity="low", metadata={})
    _assert_not_contains(drafts, "soc2", "CC6.8")
    _assert_contains(drafts, "soc2", "CC7.1")


# Rule 3: secrets

def test_secrets_maps_cc6_1():
    m = _assert_contains(map_finding(scanner_type="secret_scanning", severity="critical", metadata={}), "soc2", "CC6.1")
    assert m.confidence >= 0.9


def test_secrets_maps_a9_4():
    _assert_contains(map_finding(scanner_type="secret_scanning", severity="high", metadata={}), "iso27001", "A.9.4")


def test_secrets_maps_pci_8_3_6():
    _assert_contains(map_finding(scanner_type="secret_scanning", severity="medium", metadata={}), "pci-dss", "8.3.6")


def test_secrets_low_severity_still_maps():
    drafts = map_finding(scanner_type="secret_scanning", severity="low", metadata={})
    _assert_contains(drafts, "soc2", "CC6.1")
    _assert_contains(drafts, "iso27001", "A.9.4")
    _assert_contains(drafts, "pci-dss", "8.3.6")


# Rule 4: SAST + sensitive data

def test_sast_sensitive_data_maps_cc6_7():
    drafts = map_finding(scanner_type="sast", severity="high", metadata={"handles_sensitive_data": True})
    _assert_contains(drafts, "soc2", "CC6.7")
    _assert_contains(drafts, "pci-dss", "6.2.4")


def test_sast_without_sensitive_data_does_not_map_cc6_7():
    _assert_not_contains(map_finding(scanner_type="sast", severity="high", metadata={}), "soc2", "CC6.7")


def test_code_scanning_alias_works():
    drafts = map_finding(scanner_type="code_scanning", severity="critical", metadata={"handles_sensitive_data": True})
    _assert_contains(drafts, "soc2", "CC6.7")


# Rule 5: public-facing

def test_public_facing_maps_cc6_6():
    _assert_contains(map_finding(scanner_type="sast", severity="medium", metadata={"is_public_facing": True}), "soc2", "CC6.6")


def test_public_facing_high_maps_pci_11_3_1():
    drafts = map_finding(scanner_type="dependencies_scanning", severity="critical", metadata={"is_public_facing": True})
    _assert_contains(drafts, "pci-dss", "11.3.1")


# Rule 6: IaC

def test_iac_maps_a8_9():
    drafts = map_finding(scanner_type="iac_scanning", severity="medium", metadata={})
    _assert_contains(drafts, "iso27001", "A.8.9")
    _assert_contains(drafts, "soc2", "CC6.6")


def test_iac_public_facing_maps_a5_23():
    drafts = map_finding(scanner_type="iac_scanning", severity="high", metadata={"is_public_facing": True})
    _assert_contains(drafts, "iso27001", "A.5.23")


# Rule 7: CC7.2

def test_critical_maps_cc7_2():
    _assert_contains(map_finding(scanner_type="secret_scanning", severity="critical", metadata={}), "soc2", "CC7.2")


def test_medium_does_not_map_cc7_2():
    _assert_not_contains(map_finding(scanner_type="sast", severity="medium", metadata={}), "soc2", "CC7.2")


# Confidence validity

def test_all_confidences_in_range_secrets():
    _assert_confidence_valid(map_finding(scanner_type="secret_scanning", severity="critical", metadata={}))


def test_all_confidences_in_range_dep():
    _assert_confidence_valid(map_finding(scanner_type="dependencies_scanning", severity="high", metadata={}))


def test_all_confidences_in_range_iac():
    _assert_confidence_valid(map_finding(scanner_type="iac_scanning", severity="medium", metadata={}))


# Deduplication

def test_no_duplicate_mappings():
    drafts = map_finding(scanner_type="dependencies_scanning", severity="critical", metadata={"is_public_facing": True})
    keys = [(d.framework, d.control_id) for d in drafts]
    assert len(keys) == len(set(keys)), "Duplicate (framework, control_id) found"


# map_chain

def test_chain_always_maps_cc7_2():
    _assert_contains(map_chain(chain_type="multi_step_exploit", severity="high"), "soc2", "CC7.2")


def test_chain_high_maps_a8_8():
    _assert_contains(map_chain(chain_type="vuln_chain", severity="high"), "iso27001", "A.8.8")


def test_chain_secret_type_maps_a9_4():
    drafts = map_chain(chain_type="secret_to_resource", severity="critical")
    _assert_contains(drafts, "iso27001", "A.9.4")
    _assert_contains(drafts, "pci-dss", "8.3.6")


def test_chain_injection_type_maps_pci_6_2_4():
    _assert_contains(map_chain(chain_type="injection_to_rce", severity="critical"), "pci-dss", "6.2.4")


def test_chain_low_severity_excludes_a8_8():
    _assert_not_contains(map_chain(chain_type="low_chain", severity="low"), "iso27001", "A.8.8")


def test_chain_no_duplicates():
    drafts = map_chain(chain_type="secret_to_resource_injection_rce", severity="critical")
    keys = [(d.framework, d.control_id) for d in drafts]
    assert len(keys) == len(set(keys)), "Duplicate in chain mappings"


def test_chain_confidence_valid():
    _assert_confidence_valid(map_chain(chain_type="multi_step", severity="critical"))


# Edge cases

def test_unknown_scanner_no_crash():
    _assert_confidence_valid(map_finding(scanner_type="unknown_tool", severity="medium", metadata={}))


def test_none_severity_no_crash():
    _assert_contains(map_finding(scanner_type="secret_scanning", severity=None, metadata={}), "soc2", "CC6.1")


def test_none_metadata_no_crash():
    _assert_contains(map_finding(scanner_type="iac_scanning", severity="high", metadata=None), "iso27001", "A.8.9")
