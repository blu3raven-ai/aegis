"""Secrets scanner: verdicts come from TruffleHog provider verification only.

Secret values are never sent to an LLM, so there is no hunter/skeptic pass and
no LLM client here — the verdict is a pure function of the ``verified`` flag.
"""
from __future__ import annotations

import json

from runner.scanners.secrets.scanner import SecretsScanner, _classify_secret_verdicts


def test_provider_verified_secret_is_confirmed():
    [out] = _classify_secret_verdicts(
        [{"file": "a.py", "line": 1, "verified": True, "match": "AKIA..."}]
    )
    assert out["verdict"] == "confirmed"
    assert out["verification_metadata"]["auto_confirmed"] == "provider_verified"


def test_unverified_secret_gets_no_verdict():
    [out] = _classify_secret_verdicts(
        [{"file": "a.py", "line": 1, "verified": False, "match": "x"}]
    )
    assert out["verdict"] is None
    # No LLM ran, so no fabricated verdict / evidence / exploit chain.
    assert "exploit_chain" not in out
    assert out.get("evidence") in (None, [])


def test_missing_verified_flag_treated_as_unverified():
    [out] = _classify_secret_verdicts([{"file": "a.py", "line": 1, "match": "x"}])
    assert out["verdict"] is None


def test_classifier_does_not_mutate_input_or_emit_llm_metadata():
    finding = {"file": "a.py", "line": 1, "verified": False, "match": "super-secret"}
    [out] = _classify_secret_verdicts([finding])
    assert "verdict" not in finding  # original untouched
    md = out.get("verification_metadata", {})
    assert "model" not in md and "tokens_in" not in md


def test_verify_findings_file_writes_provider_verdicts(tmp_path):
    findings_file = tmp_path / "findings.jsonl"
    findings_file.write_text(
        json.dumps({"file": "a.py", "line": 1, "match": "AKIA...", "verified": True}) + "\n"
        + json.dumps({"file": "b.py", "line": 2, "match": "x", "verified": False}) + "\n"
    )

    SecretsScanner()._verify_findings_file(findings_file)

    rewritten = [json.loads(l) for l in findings_file.read_text().splitlines() if l.strip()]
    assert rewritten[0]["verdict"] == "confirmed"
    assert rewritten[0]["verification_metadata"]["auto_confirmed"] == "provider_verified"
    assert rewritten[1]["verdict"] is None


def test_verify_findings_file_missing_is_noop(tmp_path):
    # No exception when findings.jsonl was never written.
    SecretsScanner()._verify_findings_file(tmp_path / "absent.jsonl")


def test_scanner_does_not_import_the_llm_secret_verifier():
    from runner.scanners.secrets import scanner as mod

    # The LLM secret-verification path is gone entirely.
    assert not hasattr(mod, "verify_secret_finding")
    assert not hasattr(mod, "_maybe_verify_secrets")
    assert not hasattr(mod, "_build_llm_client")
