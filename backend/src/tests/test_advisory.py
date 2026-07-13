"""Unit tests for the advisory Markdown composer and PoC artifact builder."""
from __future__ import annotations

from src.findings.advisory import (
    compose_advisory_html,
    compose_advisory_markdown,
    poc_artifact,
)


def _finding(**kw) -> dict:
    base = {
        "id": 42,
        "title": "Untrusted pickle load on default kickoff path -> RCE",
        "severity": "high",
        "verdict": "confirmed",
        "cve": None,
        "cwe": "CWE-502",
        "repo": "github:acme/example-repo",
        "exploit_chain": "The loader unpickles a CWD file [R1].",
        "evidence": [{"file": "a/file_handler.py", "line": 166,
                      "snippet": "pickle.load(file)", "kind": "sink"}],
        "verification_metadata": {
            "impact": "Arbitrary code execution as the victim user.",
            "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
            "cvss_score": 7.8,
            "distinctness": "Different sink than the March 2026 cluster.",
            "remediation": ["Use JSON not pickle.", "Gate behind a flag."],
            "reproduction": "Plant the file, run kickoff.",
            "attack_paths": [],
            "mitigating_factors": ["Requires writing the CWD."],
            "fix": "--- a/x\n+++ b/x\n@@\n-bad\n+good",
            "poc_script": "print('pwned')",
            "poc_filename": "pickle_rce_poc.py",
            "poc_language": "python",
        },
    }
    base.update(kw)
    return base


def test_composer_includes_header_and_sections():
    md = compose_advisory_markdown(_finding())
    assert md.startswith("# Untrusted pickle load")
    assert "**Severity:** High" in md
    assert "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" in md
    assert "7.8" in md
    assert "CWE-502" in md
    assert "github:acme/example-repo" in md
    assert "## Summary" in md
    assert "## Technical Detail" in md
    assert "file_handler.py:166" in md
    assert "## Distinctness" in md
    assert "Different sink" in md
    assert "## Remediation" in md
    assert "1. Use JSON not pickle." in md
    assert "## Testing & Safe Harbor" in md  # always present


def test_composer_omits_absent_sections():
    md = compose_advisory_markdown(_finding(
        cwe=None, verification_metadata={"impact": "x"}))
    assert "CVSS:3.1" not in md          # no vector -> no CVSS line
    assert "## Distinctness" not in md   # empty -> omitted
    assert "## Remediation" not in md    # empty -> omitted
    assert "## Testing & Safe Harbor" in md  # still always present


def test_poc_artifact_prepends_safe_harbor_header():
    name, body = poc_artifact(_finding())
    assert name == "pickle_rce_poc.py"
    assert "print('pwned')" in body
    assert "Safe Harbor" in body or "safe harbor" in body.lower()
    if "Safe Harbor" in body:
        assert body.index("Safe Harbor") < body.index("print('pwned')")


def test_poc_artifact_none_when_no_script():
    assert poc_artifact(_finding(verification_metadata={"impact": "x"})) is None


def test_poc_artifact_default_filename():
    f = _finding()
    f["verification_metadata"] = {"poc_script": "echo hi", "poc_language": "bash"}
    name, _ = poc_artifact(f)
    assert name == "finding-42-poc.sh"  # derived when no filename supplied


def test_poc_artifact_sanitizes_malicious_filename():
    # A model-supplied filename with quotes / path / control chars must not be
    # able to break out of the quoted Content-Disposition value.
    f = _finding()
    f["verification_metadata"] = {
        "poc_script": "echo hi",
        "poc_language": "bash",
        "poc_filename": 'p"; drop=1\n../../etc.py',
    }
    name, _ = poc_artifact(f)
    assert '"' not in name and "/" not in name and "\n" not in name
    assert name  # never empty (falls back if nothing usable remains)


def test_compose_advisory_html_structures_and_always_has_safe_harbor():
    doc = compose_advisory_html(_finding())
    assert doc.startswith("<!DOCTYPE html>")
    assert "<h1>" in doc
    assert "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" in doc
    assert "<h2>Technical Detail</h2>" in doc
    assert "<h2>Distinctness</h2>" in doc
    assert "<h2>Remediation</h2>" in doc
    assert "Testing &amp; Safe Harbor" in doc


def test_compose_advisory_html_escapes_untrusted_content():
    # Title and evidence snippet are model/scanner-derived — they must be
    # HTML-escaped so they can't inject markup into the rendered PDF.
    f = _finding(title="SQLi in <report> filter & bypass")
    f["evidence"] = [{"file": "a.py", "line": 1, "snippet": "q = '<b>' + x", "kind": "sink"}]
    doc = compose_advisory_html(f)
    assert "&lt;report&gt;" in doc
    assert "<report>" not in doc          # raw title markup must not leak
    assert "&lt;b&gt;" in doc
    assert "'<b>'" not in doc             # raw snippet markup must not leak


def test_compose_advisory_html_omits_absent_sections():
    doc = compose_advisory_html(_finding(cwe=None, verification_metadata={"impact": "x"}))
    assert "CVSS:3.1" not in doc
    assert "<h2>Distinctness</h2>" not in doc
    assert "Testing &amp; Safe Harbor" in doc  # always present
