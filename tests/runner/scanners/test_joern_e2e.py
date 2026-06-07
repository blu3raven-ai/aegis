"""End-to-end Joern adapter tests against known-vulnerable / safe fixtures.

These tests actually invoke joern-cli — they require the runner Docker image
or a local Joern install. Skipped if joern binary is not on PATH.

Note: these are calibration tests. The .sc query scripts under
runner/scanners/code_scanning/joern_queries/ are first drafts; if any of
the vulnerable fixtures don't trigger, the corresponding query needs its
sink list broadened. If any of the safe fixtures DO trigger, the sanitizer
recognition needs tightening.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from runner.scanners.code_scanning import joern_adapter

FIXTURES = Path(__file__).parent / "fixtures" / "sast"

pytestmark = pytest.mark.skipif(
    shutil.which("joern") is None,
    reason="joern binary not on PATH — run inside the runner Docker image",
)


def _flags_for(fixture_name: str, cwe: str, tmp_path: Path) -> tuple[bool, list[dict]]:
    """Run Joern against a single-file fixture, return (flagged_expected_cwe, all_findings)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    src = FIXTURES / fixture_name
    (repo / src.name).write_bytes(src.read_bytes())
    result = joern_adapter.run(repo_path=repo, workdir=tmp_path / "work")
    flagged = any(f.get("cwe") == cwe for f in result.findings)
    return flagged, result.findings


@pytest.mark.parametrize("fixture, cwe", [
    ("cwe89_sqli.py", "CWE-89"),
    ("cwe78_cmdi.py", "CWE-78"),
    ("cwe22_path.py", "CWE-22"),
    ("cwe918_ssrf.py", "CWE-918"),
])
def test_vulnerable_fixture_is_flagged(fixture, cwe, tmp_path):
    flagged, findings = _flags_for(fixture, cwe, tmp_path)
    assert flagged, f"Joern should flag {fixture} as {cwe}. All findings: {findings}"


@pytest.mark.parametrize("fixture, cwe", [
    ("cwe89_sqli_safe.py", "CWE-89"),
    ("cwe78_cmdi_safe.py", "CWE-78"),
    ("cwe22_path_safe.py", "CWE-22"),
    ("cwe918_ssrf_safe.py", "CWE-918"),
])
def test_safe_fixture_is_not_flagged(fixture, cwe, tmp_path):
    flagged, findings = _flags_for(fixture, cwe, tmp_path)
    assert not flagged, f"Joern should NOT flag {fixture} as {cwe}. False positive findings: {findings}"
