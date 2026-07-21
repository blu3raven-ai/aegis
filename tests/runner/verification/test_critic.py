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


def test_traversal_citation_is_jailed(tmp_path):
    # A prompt-injected citation pointing outside the repo (../../) must never
    # be read off the host. The out-of-repo file exists and the snippet matches,
    # but the jail rejects the path, so it reports file_missing (oracle bit=0)
    # instead of confirming the citation.
    repo = tmp_path / "repo" / "_checkout"
    repo.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("TOPSECRET=leakme\n")

    evidence = [
        {"file": "../../outside/secret.txt", "line": 1,
         "snippet": "TOPSECRET=leakme", "kind": "code"},
    ]
    unverified, _ = verify_citations(evidence, str(repo))
    assert unverified == ["../../outside/secret.txt:1 (file_missing)"]


def test_absolute_path_citation_is_jailed(tmp_path):
    # An absolute-path citation (e.g. /etc/passwd) must also be rejected, not
    # read — even though the file exists and is readable on the host.
    repo = tmp_path / "repo" / "_checkout"
    repo.mkdir(parents=True)
    secret = tmp_path / "abs_secret.txt"
    secret.write_text("root:x:0:0\n")

    evidence = [
        {"file": str(secret), "line": 1, "snippet": "root:x:0:0", "kind": "code"},
    ]
    unverified, _ = verify_citations(evidence, str(repo))
    assert unverified == [f"{secret}:1 (file_missing)"]
