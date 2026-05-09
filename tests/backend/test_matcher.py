"""Tests for finding merge logic."""
from src.dependencies.matcher import merge_findings, enrich_with_manifest_snippets


def test_merge_deduplicates_by_advisory_and_package():
    f1 = {
        "security_advisory": {"ghsa_id": "GHSA-abc", "cve_id": "CVE-2021-001", "cvss": {"score": 5.0}, "description": "short"},
        "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}, "manifest_path": "/package.json"},
        "matched_by": ["grype"],
        "security_vulnerability": {"first_patched_version": None},
    }
    f2 = {
        "security_advisory": {"ghsa_id": "GHSA-abc", "cve_id": "CVE-2021-001", "cvss": {"score": 7.2}, "description": "longer description here"},
        "dependency": {"package": {"name": "lodash", "ecosystem": "npm"}, "manifest_path": "/package.json"},
        "matched_by": ["nvd"],
        "security_vulnerability": {"first_patched_version": {"identifier": "4.17.21"}},
    }
    merged = merge_findings([f1, f2])
    assert len(merged) == 1
    assert set(merged[0]["matched_by"]) == {"grype", "nvd"}
    assert merged[0]["security_vulnerability"]["first_patched_version"]["identifier"] == "4.17.21"
    assert merged[0]["security_advisory"]["cvss"]["score"] == 7.2
    assert "longer" in merged[0]["security_advisory"]["description"]


def test_merge_keeps_distinct_advisories():
    f1 = {
        "security_advisory": {"ghsa_id": "GHSA-aaa", "cve_id": None, "cvss": {"score": None}, "description": ""},
        "dependency": {"package": {"name": "lodash"}, "manifest_path": "/a"},
        "matched_by": ["grype"],
        "security_vulnerability": {"first_patched_version": None},
    }
    f2 = {
        "security_advisory": {"ghsa_id": "GHSA-bbb", "cve_id": None, "cvss": {"score": None}, "description": ""},
        "dependency": {"package": {"name": "lodash"}, "manifest_path": "/a"},
        "matched_by": ["grype"],
        "security_vulnerability": {"first_patched_version": None},
    }
    assert len(merge_findings([f1, f2])) == 2


def test_enrich_with_manifest_snippets_finds_package():
    findings = [{
        "dependency": {"package": {"name": "lodash"}, "manifest_path": "/package.json"},
        "manifest_snippet": None,
        "manifest_match_line": None,
    }]
    manifests = {"package.json": '{\n  "dependencies": {\n    "lodash": "^4.17.20"\n  }\n}'}
    enriched = enrich_with_manifest_snippets(findings, manifests)
    assert enriched[0]["manifest_snippet"] is not None
    assert enriched[0]["manifest_match_line"] is not None
    assert "lodash" in enriched[0]["manifest_snippet"]


def test_enrich_with_empty_manifests():
    findings = [{
        "dependency": {"package": {"name": "lodash"}, "manifest_path": "/package.json"},
        "manifest_snippet": None,
        "manifest_match_line": None,
    }]
    enriched = enrich_with_manifest_snippets(findings, {})
    assert enriched[0]["manifest_snippet"] is None
