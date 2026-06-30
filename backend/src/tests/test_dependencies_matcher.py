"""Contract tests for dependency finding dedup + manifest-snippet enrichment.

`merge_findings` collapses duplicates by (advisory, package, manifest) and unions
their `matched_by` provenance; `enrich_with_manifest_snippets` locates the
package in stored manifest text and attaches a bounded code snippet. Both are
pure and back the dependency ingest path.
"""
from __future__ import annotations

from src.dependencies.matcher import (
    CONTEXT_LINES,
    enrich_with_manifest_snippets,
    merge_findings,
)


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


# ----- enrich_with_manifest_snippets ---------------------------------------

def _dep_finding(pkg, manifest):
    return {"dependency": {"package": {"name": pkg}, "manifest_path": manifest}}


def test_snippet_centres_on_match_line():
    lines = [f"line{i}" for i in range(1, 21)]
    lines[9] = "  lodash: ^4.17.21"  # 1-indexed line 10
    content = "\n".join(lines)
    findings = [_dep_finding("lodash", "package.json")]

    out = enrich_with_manifest_snippets(findings, {"package.json": content})

    assert out[0]["manifest_match_line"] == 10
    snippet_lines = out[0]["manifest_snippet"].split("\n")
    assert "  lodash: ^4.17.21" in snippet_lines
    # bounded to a context window around the match (<= 2*CONTEXT_LINES + 1)
    assert len(snippet_lines) <= 2 * CONTEXT_LINES + 1


def test_no_match_falls_back_to_head_and_line_zero():
    content = "\n".join(f"line{i}" for i in range(1, 30))
    findings = [_dep_finding("absent-pkg", "package.json")]

    out = enrich_with_manifest_snippets(findings, {"package.json": content})

    assert out[0]["manifest_match_line"] == 0
    assert out[0]["manifest_snippet"].split("\n") == [f"line{i}" for i in range(1, 16)]


def test_path_variant_resolution_via_safe_key():
    # Manifest stored under the slash-encoded ("safe") key still resolves.
    content = "dep: foopkg\n"
    findings = [_dep_finding("foopkg", "/src/app/requirements.txt")]

    out = enrich_with_manifest_snippets(findings, {"src__app__requirements.txt": content})

    assert out[0]["manifest_match_line"] == 1
    assert "foopkg" in out[0]["manifest_snippet"]


def test_skips_when_missing_path_pkg_or_content():
    # missing manifest_path
    f1 = {"dependency": {"package": {"name": "x"}, "manifest_path": ""}}
    # missing package name
    f2 = {"dependency": {"package": {"name": ""}, "manifest_path": "package.json"}}
    # path/pkg present but no stored content
    f3 = _dep_finding("x", "package.json")

    out = enrich_with_manifest_snippets([f1, f2, f3], {})
    for f in out:
        assert "manifest_snippet" not in f
        assert "manifest_match_line" not in f
