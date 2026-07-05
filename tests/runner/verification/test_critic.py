"""Tests for runner.verification.critic — citation grounding."""
from __future__ import annotations

from pathlib import Path

import pytest

from runner.verification.critic import verify_citations


def test_file_citation_grounded(tmp_path):
    p = tmp_path / "src" / "a.py"
    p.parent.mkdir(parents=True)
    p.write_text("line1\nimport requests\nline3\n")

    evidence = [
        {
            "file": "src/a.py",
            "line": 2,
            "snippet": "import requests",
            "kind": "import_site",
        }
    ]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert unverified == []


def test_file_citation_missing_file(tmp_path):
    evidence = [
        {"file": "missing.py", "line": 1, "snippet": "x", "kind": "import_site"}
    ]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert any("file_missing" in u for u in unverified)


def test_file_citation_snippet_not_found(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("totally different content\n")

    evidence = [{"file": "a.py", "line": 1, "snippet": "import requests", "kind": "source"}]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert any("snippet_not_found" in u for u in unverified)


def test_file_citation_within_two_line_window(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("line1\nline2\nimport requests\nline4\nline5\n")

    # Cite line 1 but the actual import is at line 3 — still within ±2 lines
    evidence = [{"file": "a.py", "line": 1, "snippet": "import requests", "kind": "source"}]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert unverified == []


def test_advisory_citation_grounded_by_source_and_snippet(tmp_path):
    evidence = [
        {
            "kind": "advisory",
            "source": "CVE-2021-23337",
            "snippet": "Prototype pollution in lodash via _.defaultsDeep",
        }
    ]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert unverified == []


def test_advisory_citation_missing_source(tmp_path):
    evidence = [{"kind": "advisory", "snippet": "some text"}]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert any("missing_source_or_snippet" in u for u in unverified)


def test_advisory_citation_missing_snippet(tmp_path):
    evidence = [{"kind": "advisory", "source": "CVE-2021-23337"}]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert any("missing_source_or_snippet" in u for u in unverified)


def test_mixed_evidence_advisory_plus_file(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("import lodash\n")

    evidence = [
        {"kind": "advisory", "source": "CVE-X", "snippet": "prototype pollution"},
        {"kind": "import_site", "file": "a.py", "line": 1, "snippet": "import lodash"},
    ]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    assert unverified == []


def test_advisory_citation_no_file_lookup_attempted(tmp_path):
    """An advisory citation must not crash even if it has an irrelevant 'file' field."""
    evidence = [
        {
            "kind": "advisory",
            "source": "CVE-X",
            "snippet": "vuln",
            "file": "totally/missing/path.py",
            "line": 9999,
        }
    ]
    unverified, _ = verify_citations(evidence, str(tmp_path))
    # The advisory citation is valid (has source + snippet); the file
    # field should be ignored since kind=advisory.
    assert unverified == []
