"""Integration tests for SCA verification wired into the dependencies scanner."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runner.scanners.dependencies.scanner import DependenciesScanner
from runner.verification.llm_client import LlmResponse


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = []
        self._model = "stub"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        return LlmResponse(
            content=self._r.pop(0),
            tokens_in=100,
            tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


def _make_findings_jsonl(out_dir: Path, findings: list[dict]) -> None:
    fp = out_dir / "findings.jsonl"
    fp.write_text("\n".join(json.dumps(f) for f in findings) + "\n")


def _basic_finding(**overrides) -> dict:
    base = {
        "advisoryId": "CVE-2021-23337",
        "advisoryAliases": ["GHSA-35jh-r3h4-6jhm"],
        "packageName": "lodash",
        "packageVersion": "4.17.20",
        "ecosystem": "npm",
        "severity": "high",
        "cvssScore": 7.2,
        "fixedVersion": "4.17.21",
        "fixState": "fixed",
        "manifestPath": "/package.json",
        "manifestSnippet": '"lodash": "4.17.20"',
        "summary": "Prototype pollution in lodash.",
        "description": "Versions prior to 4.17.21 are vulnerable.",
        "repository": "acme__widget",
        "advisoryDetail": {
            "advisoryId": "CVE-2021-23337",
            "summary": "Prototype pollution",
            "description": "Versions of lodash prior to 4.17.21 are vulnerable.",
            "references": [],
            "cwes": ["CWE-1321"],
            "vulnerableVersionRange": "< 4.17.21",
            "publishedAt": "",
            "sources": ["nvd"],
        },
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# LLM disabled path
# ---------------------------------------------------------------------------


def test_verify_marks_findings_llm_disabled_when_no_key(tmp_path, monkeypatch):
    """No BYO LLM key configured — every finding gets verdict=None + skip reason."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    _make_findings_jsonl(tmp_path, [_basic_finding()])

    scanner = DependenciesScanner()
    scanner._verify_findings_file(tmp_path / "findings.jsonl", tmp_path)

    line = (tmp_path / "findings.jsonl").read_text().strip()
    f = json.loads(line)
    assert f["verdict"] is None
    assert f["verification_metadata"]["skipped"] == "llm_disabled"


def test_verify_no_op_when_findings_file_missing(tmp_path):
    scanner = DependenciesScanner()
    # Should not raise
    scanner._verify_findings_file(tmp_path / "missing.jsonl", tmp_path)


# ---------------------------------------------------------------------------
# Prefilter short-circuits
# ---------------------------------------------------------------------------


def test_prefilter_rules_out_dev_only_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "any-value")  # build LLM but it shouldn't be called

    finding = _basic_finding(manifestPath="/requirements-dev.txt", ecosystem="pypi")
    _make_findings_jsonl(tmp_path, [finding])

    scanner = DependenciesScanner()
    # Stub LLM that would explode if invoked
    llm = _StubLlm([])

    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "ruled_out"
    assert verified[0]["verification_metadata"]["prefilter"]["reason"] == "dev_only_manifest"
    assert llm.calls == []  # never invoked


def test_prefilter_rules_out_when_no_import_sites_collected(tmp_path):
    finding = _basic_finding(ecosystem="npm", repository="acme__widget")
    # Repo checkout exists but has no JS files importing lodash
    repo_root = tmp_path / "acme__widget" / "_checkout"
    repo_root.mkdir(parents=True)
    (repo_root / "src").mkdir()
    (repo_root / "src" / "other.js").write_text("// nothing of interest\n")

    scanner = DependenciesScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "ruled_out"
    assert verified[0]["verification_metadata"]["prefilter"]["reason"] == "no_import_sites"
    assert llm.calls == []


# ---------------------------------------------------------------------------
# Full verification path
# ---------------------------------------------------------------------------


def test_full_verify_invokes_llm_when_imports_present(tmp_path):
    finding = _basic_finding(repository="acme__widget")
    repo_root = tmp_path / "acme__widget" / "_checkout"
    repo_root.mkdir(parents=True)
    (repo_root / "src").mkdir()
    (repo_root / "src" / "app.js").write_text("const _ = require('lodash');\n")

    scanner = DependenciesScanner()
    llm = _StubLlm([
        json.dumps({
            "exploit_chain": "lodash imported and prototype pollution surface reachable",
            "evidence": [
                {
                    "kind": "advisory",
                    "source": "CVE-2021-23337",
                    "snippet": "prototype pollution",
                },
                {
                    "kind": "import_site",
                    "file": "src/app.js",
                    "line": 1,
                    "snippet": "const _ = require('lodash');",
                },
            ],
        }),
        json.dumps({"mitigation_found": False, "reasoning": ""}),
    ])

    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "confirmed"
    assert verified[0]["exploit_chain"]
    assert len(llm.calls) == 2  # Hunter + Skeptic


def test_below_severity_skips_llm(tmp_path):
    finding = _basic_finding(severity="negligible", repository="acme__widget")
    repo_root = tmp_path / "acme__widget" / "_checkout"
    repo_root.mkdir(parents=True)
    (repo_root / "src").mkdir()
    (repo_root / "src" / "app.js").write_text("const _ = require('lodash');\n")

    scanner = DependenciesScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "below_severity"
    assert llm.calls == []


def test_budget_exhausted_yields_possible(tmp_path):
    finding = _basic_finding(repository="acme__widget")
    repo_root = tmp_path / "acme__widget" / "_checkout"
    repo_root.mkdir(parents=True)
    (repo_root / "app.js").write_text("require('lodash');\n")

    from runner.verification.budget import ScanBudget
    exhausted = ScanBudget(scan_budget=0, daily_remaining=10_000)

    scanner = DependenciesScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=exhausted,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"]["skipped"] == "scan_budget"
    assert llm.calls == []


def test_llm_error_recorded_does_not_raise(tmp_path):
    finding = _basic_finding(repository="acme__widget")
    repo_root = tmp_path / "acme__widget" / "_checkout"
    repo_root.mkdir(parents=True)
    (repo_root / "app.js").write_text("require('lodash');\n")

    class _ExplodingLlm:
        _model = "boom"

        def chat(self, *a, **kw):
            raise RuntimeError("upstream timeout")

    scanner = DependenciesScanner()
    verified = scanner._maybe_verify_sca(
        findings=[finding],
        out_dir=tmp_path,
        llm=_ExplodingLlm(),
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert "llm_error" in verified[0]["verification_metadata"]["skipped"]


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------


def test_cleanup_checkouts_removes_all_repo_checkouts(tmp_path):
    (tmp_path / "acme__widget" / "_checkout" / "src").mkdir(parents=True)
    (tmp_path / "acme__widget" / "_checkout" / "src" / "x.js").write_text("//\n")
    (tmp_path / "other__pkg" / "_checkout").mkdir(parents=True)

    scanner = DependenciesScanner()
    scanner._cleanup_checkouts(tmp_path)

    assert not (tmp_path / "acme__widget" / "_checkout").exists()
    assert not (tmp_path / "other__pkg" / "_checkout").exists()
    # repo_out itself preserved (holds findings.json, manifests/, etc.)
    assert (tmp_path / "acme__widget").exists()


def test_cleanup_handles_nested_org_repo_structure(tmp_path):
    nested = tmp_path / "acme" / "widget" / "_checkout"
    nested.mkdir(parents=True)
    (nested / "x.js").write_text("//\n")

    scanner = DependenciesScanner()
    scanner._cleanup_checkouts(tmp_path)

    assert not nested.exists()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _unlimited_budget():
    from runner.verification.budget import ScanBudget
    return ScanBudget(scan_budget=1_000_000, daily_remaining=1_000_000)
