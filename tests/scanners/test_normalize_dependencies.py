"""Tests for normalize-dependencies.py manifest snippet enrichment."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import importlib.util
import pytest

# Load module with hyphenated filename
_spec = importlib.util.spec_from_file_location(
    "normalize_dependencies",
    Path(__file__).parent.parent.parent / "scanners" / "dependencies" / "scripts" / "normalize-dependencies.py",
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]
normalize_file = _mod.normalize_file


def _grype_match(pkg_name: str, manifest_path: str, advisory_id: str = "CVE-2024-1234") -> dict:
    """Minimal Grype match structure."""
    return {
        "vulnerability": {
            "id": advisory_id,
            "severity": "High",
            "description": "desc",
            "dataSource": "",
            "fix": {"versions": ["2.0.0"], "state": "fixed"},
            "cvss": [],
            "aliases": [],
        },
        "artifact": {
            "name": pkg_name,
            "version": "1.0.0",
            "type": "python",
            "locations": [{"path": manifest_path}],
        },
    }


def test_manifest_snippet_with_leading_slash(tmp_path: Path):
    """Grype reports /requirements.txt but manifest saved as requirements.txt — must still match."""
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    (manifests_dir / "requirements.txt").write_text("torch==2.1.2\nnumpy==1.24.0")

    grype_json = {"matches": [_grype_match("torch", "/requirements.txt")]}
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(grype_json))

    results = normalize_file(findings_file, "acme-org", "ml-repo", "abc123", manifests_dir)

    assert len(results) == 1
    assert results[0]["manifestSnippet"] is not None
    assert "torch" in results[0]["manifestSnippet"]
    assert results[0]["manifestMatchLine"] == 1


def test_manifest_snippet_without_leading_slash(tmp_path: Path):
    """Sanity: path without leading slash still works."""
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    (manifests_dir / "requirements.txt").write_text("flask==2.0\nrequests==2.28.0")

    grype_json = {"matches": [_grype_match("flask", "requirements.txt")]}
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(grype_json))

    results = normalize_file(findings_file, "acme-org", "web-repo", "abc123", manifests_dir)

    assert results[0]["manifestSnippet"] is not None
    assert "flask" in results[0]["manifestSnippet"]


def test_manifest_snippet_nested_path_with_leading_slash(tmp_path: Path):
    """Deep path /src/requirements.txt → saved as src__requirements.txt."""
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    (manifests_dir / "src__requirements.txt").write_text("django==4.0\npsycopg2==2.9")

    grype_json = {"matches": [_grype_match("django", "/src/requirements.txt")]}
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(grype_json))

    results = normalize_file(findings_file, "acme-org", "svc-repo", "abc123", manifests_dir)

    assert results[0]["manifestSnippet"] is not None
    assert "django" in results[0]["manifestSnippet"]


def test_no_manifest_dir(tmp_path: Path):
    """Missing manifests_dir gracefully produces null snippet."""
    grype_json = {"matches": [_grype_match("torch", "/requirements.txt")]}
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(grype_json))

    results = normalize_file(findings_file, "acme-org", "repo", "HEAD", None)

    assert results[0]["manifestSnippet"] is None
    assert results[0]["manifestMatchLine"] is None


def test_package_name_not_matched_as_substring(tmp_path: Path):
    """torch must not match torch_stable in a find-links URL; should land on torch==2.1.2."""
    manifests_dir = tmp_path / "manifests"
    manifests_dir.mkdir()
    content = (
        "-f https://download.pytorch.org/whl/cu121/torch_stable.html\n"
        "faster-whisper==1.1.1\n"
        "torch==2.1.2\n"
        "torchaudio==2.1.2\n"
        "torchvision==0.16.2\n"
    )
    (manifests_dir / "requirements-ml.txt").write_text(content)

    grype_json = {"matches": [_grype_match("torch", "/requirements-ml.txt")]}
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(grype_json))

    results = normalize_file(findings_file, "acme-org", "ml-repo", "abc123", manifests_dir)

    assert results[0]["manifestMatchLine"] == 3, "should match torch==2.1.2 on line 3, not the find-links URL"
    assert "torch==2.1.2" in results[0]["manifestSnippet"]
