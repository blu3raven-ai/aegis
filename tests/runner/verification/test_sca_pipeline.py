"""Tests for runner.verification.verifiers.sca.verify_sca_finding."""
from __future__ import annotations

import json

from runner.verification.llm_client import LlmResponse
from runner.verification.verifiers.sca import verify_sca_finding


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = []
        self._model = "stub-model"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        content = self._r.pop(0)
        return LlmResponse(
            content=content,
            tokens_in=100,
            tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


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
        "description": "Versions prior to 4.17.21 are vulnerable to prototype pollution.",
        "advisoryDetail": {
            "advisoryId": "CVE-2021-23337",
            "summary": "Prototype pollution",
            "description": (
                "Versions of lodash prior to 4.17.21 are vulnerable to "
                "prototype pollution via _.defaultsDeep when handling "
                "attacker-controlled object keys."
            ),
            "references": ["https://github.com/lodash/lodash/pull/5085"],
            "cwes": ["CWE-1321"],
            "vulnerableVersionRange": "< 4.17.21",
            "publishedAt": "2021-02-15T11:15:00Z",
            "sources": ["nvd", "osv"],
        },
    }
    base.update(overrides)
    return base


def _hunter_chain_json(chain: str, evidence: list[dict]) -> str:
    return json.dumps({"exploit_chain": chain, "evidence": evidence})


def _skeptic_json(mitigation: bool, **kw) -> str:
    return json.dumps({
        "mitigation_found": mitigation,
        "mitigation_file": kw.get("file"),
        "mitigation_line": kw.get("line"),
        "mitigation_snippet": kw.get("snippet"),
        "reasoning": kw.get("reasoning", ""),
    })


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def test_hunter_no_chain_yields_possible(tmp_path):
    llm = _StubLlm([_hunter_chain_json("", [])])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "possible"
    assert result.verification_metadata["reason"] == "hunter_no_chain"
    # Only the Hunter ran — Skeptic skipped
    assert len(llm.calls) == 1


def test_hunter_confirms_then_skeptic_agrees_yields_confirmed(tmp_path):
    # Create the user-code file the Hunter cites
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.js").write_text("const _ = require('lodash');\n")
    (tmp_path / "package.json").write_text('"lodash": "4.17.20"\n')

    llm = _StubLlm([
        _hunter_chain_json(
            "lodash imported in src/app.js; vulnerable _.defaultsDeep available",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2021-23337",
                    "snippet": "Prototype pollution via _.defaultsDeep",
                },
                {
                    "kind": "import_site",
                    "file": "src/app.js",
                    "line": 1,
                    "snippet": "const _ = require('lodash');",
                },
            ],
        ),
        _skeptic_json(False, reasoning="no mitigation found"),
    ])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 200
    assert result.tokens_out == 100
    assert "advisory" in {e["kind"] for e in result.evidence}


def test_skeptic_finds_dev_only_mitigation_yields_ruled_out(tmp_path):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "build.js").write_text("const _ = require('lodash');\n")

    llm = _StubLlm([
        _hunter_chain_json(
            "lodash imported in scripts/build.js",
            [
                {
                    "kind": "import_site",
                    "file": "scripts/build.js",
                    "line": 1,
                    "snippet": "const _ = require('lodash');",
                }
            ],
        ),
        _skeptic_json(
            True,
            file="package.json",
            line=10,
            snippet='"lodash": "4.17.20"  // devDependencies',
            reasoning="lodash is a devDependency and only used in build scripts",
        ),
    ])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "ruled_out"
    rr = result.verification_metadata["ruled_out_reason"]
    assert rr["file"] == "package.json"
    assert "devDependency" in rr["reasoning"]


def test_unverified_file_citation_downgrades_to_needs_verify(tmp_path):
    # No file created at the cited path
    llm = _StubLlm([
        _hunter_chain_json(
            "chain text",
            [
                {
                    "kind": "import_site",
                    "file": "src/missing.js",
                    "line": 1,
                    "snippet": "const _ = require('lodash');",
                }
            ],
        ),
        _skeptic_json(False),
    ])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "needs_verify"
    assert "unverified_citations" in result.verification_metadata


def test_advisory_only_evidence_is_acceptable(tmp_path):
    """If the Hunter's evidence is purely an advisory citation (no file:line),
    the critic still passes it and the verdict reaches confirmed."""
    llm = _StubLlm([
        _hunter_chain_json(
            "chain",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2021-23337",
                    "snippet": "Vulnerable function _.defaultsDeep",
                }
            ],
        ),
        _skeptic_json(False),
    ])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "confirmed"


# ---------------------------------------------------------------------------
# Import-site collection integration
# ---------------------------------------------------------------------------


def test_import_sites_collected_and_count_recorded(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text("require('lodash');\n")
    (tmp_path / "src" / "b.js").write_text("require('lodash');\n")

    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verification_metadata["import_site_count"] == 2


def test_zero_import_sites_when_package_unused(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text("// no imports at all\n")

    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verification_metadata["import_site_count"] == 0
    assert result.verdict == "possible"


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_malformed_hunter_json_falls_back_safely(tmp_path):
    llm = _StubLlm([
        "this is not json at all",
        _skeptic_json(False),
    ])

    result = verify_sca_finding(
        finding=_basic_finding(),
        repo_root=str(tmp_path),
        llm=llm,
    )
    # Pydantic validation on the hunter response: unparseable JSON → needs_verify
    assert result.verdict == "needs_verify"


def test_missing_advisory_detail_does_not_crash(tmp_path):
    finding = _basic_finding()
    finding["advisoryDetail"] = None

    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_sca_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "possible"


def test_unknown_ecosystem_skips_import_search(tmp_path):
    (tmp_path / "a.go").write_text('import "lodash"\n')

    finding = _basic_finding(ecosystem="go")
    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_sca_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    # Ecosystem unsupported by the collector → 0 sites, no crash
    assert result.verification_metadata["import_site_count"] == 0
