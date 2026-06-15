"""Tests for runner.verification.helpers.prefilter."""
from __future__ import annotations

import pytest

from runner.verification.helpers.prefilter import prefilter_sca_finding


def _finding(**overrides) -> dict:
    base = {
        "advisoryId": "CVE-2021-23337",
        "packageName": "lodash",
        "packageVersion": "4.17.20",
        "ecosystem": "npm",
        "severity": "high",
        "manifestPath": "/package.json",
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Dev-only manifest detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "manifest_path",
    [
        "/requirements-dev.txt",
        "/requirements-test.txt",
        "/dev-requirements.txt",
        "/test-requirements.txt",
        "/services/api/requirements_dev.txt",
        "/services/api/dev_requirements.txt",
    ],
)
def test_dev_only_manifest_skips_llm(manifest_path):
    decision = prefilter_sca_finding(
        _finding(manifestPath=manifest_path, ecosystem="pypi")
    )
    assert decision.skip_llm is True
    assert decision.verdict == "ruled_out"
    assert decision.reason == "dev_only_manifest"


@pytest.mark.parametrize(
    "manifest_path",
    [
        "/requirements.txt",
        "/package.json",
        "/pyproject.toml",
        "/services/api/requirements.txt",
        "/go.mod",
    ],
)
def test_prod_manifest_does_not_short_circuit(manifest_path):
    decision = prefilter_sca_finding(
        _finding(manifestPath=manifest_path, ecosystem="pypi"),
        import_sites=[{"file": "x.py", "line": 1, "snippet": "import x", "kind": "import"}],
    )
    assert decision.skip_llm is False
    assert decision.reason == "none"


# ---------------------------------------------------------------------------
# No-import-sites rule
# ---------------------------------------------------------------------------


def test_no_import_sites_skips_when_ecosystem_supported():
    decision = prefilter_sca_finding(_finding(ecosystem="npm"), import_sites=[])
    assert decision.skip_llm is True
    assert decision.verdict == "ruled_out"
    assert decision.reason == "no_import_sites"


def test_no_import_sites_does_not_skip_when_ecosystem_unsupported():
    decision = prefilter_sca_finding(_finding(ecosystem="go"), import_sites=[])
    assert decision.skip_llm is False
    assert decision.reason == "none"


def test_no_import_sites_does_not_skip_when_sites_unknown():
    """import_sites=None means 'we didn't look', not 'there are zero'."""
    decision = prefilter_sca_finding(_finding(ecosystem="npm"), import_sites=None)
    assert decision.skip_llm is False
    assert decision.reason == "none"


def test_has_import_sites_does_not_skip():
    decision = prefilter_sca_finding(
        _finding(ecosystem="npm"),
        import_sites=[{"file": "x.js", "line": 1, "snippet": "require('lodash')", "kind": "require"}],
    )
    assert decision.skip_llm is False


# ---------------------------------------------------------------------------
# Rule precedence
# ---------------------------------------------------------------------------


def test_dev_manifest_takes_precedence_over_import_sites():
    """Dev-only is a stronger signal than 'has imports', since dev imports
    of a vulnerable package still aren't a production risk."""
    decision = prefilter_sca_finding(
        _finding(manifestPath="/requirements-dev.txt", ecosystem="pypi"),
        import_sites=[
            {"file": "tests/x.py", "line": 1, "snippet": "import x", "kind": "import"}
        ],
    )
    assert decision.skip_llm is True
    assert decision.reason == "dev_only_manifest"


def test_empty_manifest_path_does_not_skip_on_manifest_rule():
    decision = prefilter_sca_finding(_finding(manifestPath=""), import_sites=[
        {"file": "x.py", "line": 1, "snippet": "import x", "kind": "import"}
    ])
    assert decision.skip_llm is False


def test_to_dict_round_trip():
    decision = prefilter_sca_finding(
        _finding(manifestPath="/requirements-dev.txt", ecosystem="pypi")
    )
    d = decision.to_dict()
    assert d["skip_llm"] is True
    assert d["verdict"] == "ruled_out"
    assert d["reason"] == "dev_only_manifest"
    assert d["metadata"]["manifestPath"] == "/requirements-dev.txt"
