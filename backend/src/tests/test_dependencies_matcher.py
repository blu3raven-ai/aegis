"""Contract tests for dependency finding dedup.

`merge_findings` collapses duplicates by (advisory, package, manifest) and unions
their `matched_by` provenance. Pure, and backs the dependency ingest path.
"""
from __future__ import annotations

from src.dependencies.matcher import merge_findings


def _finding(ghsa, pkg, manifest, cvss, matched_by, desc=""):
    return {
        "security_advisory": {"ghsa_id": ghsa, "cvss": {"score": cvss}, "description": desc},
        "dependency": {"package": {"name": pkg}, "manifest_path": manifest},
        "matched_by": list(matched_by),
    }


# ----- merge_findings -------------------------------------------------------

def test_duplicates_collapse_and_union_matched_by():
    findings = [
        _finding("GHSA-1", "lodash", "package.json", 5.0, ["osv"]),
        _finding("GHSA-1", "lodash", "package.json", 5.0, ["ghsa"]),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    assert merged[0]["matched_by"] == ["ghsa", "osv"]  # sorted union


def test_distinct_keys_not_merged():
    findings = [
        _finding("GHSA-1", "lodash", "package.json", 5.0, ["osv"]),
        _finding("GHSA-2", "lodash", "package.json", 5.0, ["osv"]),       # diff advisory
        _finding("GHSA-1", "react", "package.json", 5.0, ["osv"]),        # diff package
        _finding("GHSA-1", "lodash", "sub/package.json", 5.0, ["osv"]),   # diff manifest
    ]
    assert len(merge_findings(findings)) == 4


def test_higher_cvss_wins_on_survivor():
    findings = [
        _finding("GHSA-1", "lodash", "package.json", 5.0, ["osv"]),
        _finding("GHSA-1", "lodash", "package.json", 9.0, ["ghsa"]),
    ]
    merged = merge_findings(findings)
    assert len(merged) == 1
    assert merged[0]["security_advisory"]["cvss"]["score"] == 9.0
