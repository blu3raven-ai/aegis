"""Tests for runner.verification.verifiers.container.verify_container_finding."""
from __future__ import annotations

import json

from runner.verification.llm_client import LlmResponse
from runner.verification.verifiers.container import verify_container_finding


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
        "advisoryId": "CVE-2023-12345",
        "advisoryAliases": ["GHSA-aaaa-bbbb-cccc"],
        "packageName": "openssl",
        "packageVersion": "1.1.1k-r0",
        "ecosystem": "apk",
        "severity": "high",
        "cvssScore": 7.5,
        "fixedVersion": "1.1.1l-r0",
        "fixState": "fixed",
        "manifestPath": "/lib/apk/db/installed",
        "manifestSnippet": "P:openssl\nV:1.1.1k-r0",
        "summary": "Buffer overflow in openssl",
        "description": "An attacker can trigger a heap overflow via crafted TLS handshake input.",
        "imageName": "acme-org/web",
        "imageTag": "1.2.3",
        "imageDigest": "sha256:abcdef0123",
        "advisoryDetail": {
            "advisoryId": "CVE-2023-12345",
            "summary": "Buffer overflow",
            "description": (
                "openssl versions prior to 1.1.1l are vulnerable to a heap "
                "overflow via the SSL_read API on TLS server sockets."
            ),
            "references": ["https://www.openssl.org/news/secadv/20230601.txt"],
            "cwes": ["CWE-122"],
            "vulnerableVersionRange": "< 1.1.1l",
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


def test_hunter_no_chain_yields_possible():
    llm = _StubLlm([_hunter_chain_json("", [])])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "possible"
    assert result.verification_metadata["reason"] == "hunter_no_chain"
    # Only the Hunter ran — Skeptic skipped
    assert len(llm.calls) == 1


def test_hunter_confirms_then_skeptic_disagrees_yields_confirmed():
    llm = _StubLlm([
        _hunter_chain_json(
            "image runs an HTTPS server using openssl; SSL_read reachable from request path",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "heap overflow via SSL_read",
                },
                {
                    "kind": "context",
                    "file": "/lib/apk/db/installed",
                    "line": 1,
                    "snippet": "P:openssl",
                },
            ],
        ),
        _skeptic_json(False, reasoning="no mitigation found"),
    ])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 200
    assert result.tokens_out == 100
    assert "advisory" in {e["kind"] for e in result.evidence}


def test_skeptic_finds_build_only_mitigation_yields_ruled_out():
    llm = _StubLlm([
        _hunter_chain_json(
            "openssl present in image",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "heap overflow via SSL_read",
                }
            ],
        ),
        _skeptic_json(
            True,
            file="/lib/apk/db/installed",
            line=1,
            snippet="P:openssl",
            reasoning="image is a build-stage artifact, openssl never invoked at runtime",
        ),
    ])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "ruled_out"
    rr = result.verification_metadata["ruled_out_reason"]
    assert rr["file"] == "/lib/apk/db/installed"
    assert "build-stage" in rr["reasoning"]


def test_advisory_only_evidence_is_acceptable():
    """v1 has no mechanical critic, so advisory-only evidence reaches confirmed."""
    llm = _StubLlm([
        _hunter_chain_json(
            "openssl exposed via TLS port",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "Vulnerable handshake path",
                }
            ],
        ),
        _skeptic_json(False),
    ])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "confirmed"


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_malformed_hunter_json_falls_back_safely():
    llm = _StubLlm([
        "not json at all",
        _skeptic_json(False),
    ])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")
    # Skeptic must NOT be called after a hunter schema failure
    assert len(llm.calls) == 1


def test_malformed_skeptic_json_falls_back_to_needs_verify():
    llm = _StubLlm([
        _hunter_chain_json(
            "chain",
            [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "heap overflow",
                }
            ],
        ),
        "garbage",
    ])

    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verdict == "needs_verify"
    assert "skeptic_schema_invalid" in result.verification_metadata.get("reason", "")


def test_missing_advisory_detail_does_not_crash():
    finding = _basic_finding()
    finding["advisoryDetail"] = None

    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_container_finding(
        finding=finding,
        llm=llm,
    )
    assert result.verdict == "possible"


def test_records_scanner_in_metadata():
    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_container_finding(
        finding=_basic_finding(),
        llm=llm,
    )
    assert result.verification_metadata["scanner"] == "container"
    assert result.verification_metadata["model"] == "stub-model"
    assert result.verification_metadata["prompt_hashes"] == ["h-1"]
