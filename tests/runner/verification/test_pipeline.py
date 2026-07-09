"""Verification pipeline tests."""
from __future__ import annotations

from runner.verification.llm_client import LlmClient, LlmResponse
from runner.verification.pipeline import (
    run_fp_detection,
    run_tp_reasoning,
    verify_finding,
)


class _StubLlm(LlmClient):
    """Scripts ``chat`` so the inherited ``chat_json`` repair loop is exercised."""

    def __init__(self, responses):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub-model")
        self._r = list(responses)
        self.calls = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        content = self._r.pop(0)
        return LlmResponse(content=content, tokens_in=100, tokens_out=50,
                           prompt_hash=f"h-{len(self.calls)}")


def test_hunter_confirms_then_skeptic_agrees_yields_confirmed():
    llm = _StubLlm([
        '{"exploit_chain":"x reaches y","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 200
    assert result.tokens_out == 100


def test_confirmed_finding_surfaces_reproduction_from_hunter():
    llm = _StubLlm([
        '{"exploit_chain":"x reaches y [R1]","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}],'
        '"reproduction":"POST /x with a crafted body"}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.verification_metadata["reproduction"] == "POST /x with a crafted body"


def test_non_confirmed_finding_omits_reproduction():
    # needs_verify (unverified citation) must not carry repro steps — that would
    # overstate confidence in an unconfirmed chain.
    llm = _StubLlm([
        '{"exploit_chain":"x [R1]","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}],'
        '"reproduction":"do the thing"}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: (["a.py:1"], []),  # unverified citation → needs_verify
    )
    assert result.verdict == "needs_verify"
    assert "reproduction" not in result.verification_metadata


def test_skeptic_finds_mitigation_yields_ruled_out():
    llm = _StubLlm([
        '{"exploit_chain":"x","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":true,"mitigation_file":"src/auth.py","mitigation_line":10,'
        '"mitigation_snippet":"if not is_authenticated: abort(401)","reasoning":"auth gate"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "ruled_out"
    assert result.verification_metadata["ruled_out_reason"]["file"] == "src/auth.py"


def test_unverified_citations_cap_at_needs_verify():
    llm = _StubLlm([
        '{"exploit_chain":"x","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}',
        '{"mitigation_found":false}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: (["a.py:1 (not_found)"], []),
    )
    assert result.verdict == "needs_verify"
    assert "unverified_citations" in result.verification_metadata


def test_hunter_returns_no_chain_yields_possible():
    llm = _StubLlm(['{"exploit_chain":"","evidence":[]}'])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
    )
    assert result.verdict == "possible"


_FINDING = {"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"}
_GOOD_HUNTER = (
    '{"exploit_chain":"x reaches y",'
    '"evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}]}'
)
_GOOD_SKEPTIC = '{"mitigation_found":false,"reasoning":"none"}'


def test_hunter_malformed_then_valid_recovers_verdict():
    """A malformed first hunter turn is repaired, not dropped to needs_verify."""
    llm = _StubLlm(["not json at all", _GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    # Hunter cost one repair (bad + good) plus one skeptic call.
    assert len(llm.calls) == 3
    # The repair conversation carried the bad content + a repair user turn.
    repair_convo = llm.calls[1]
    assert any(m["role"] == "assistant" and m["content"] == "not json at all" for m in repair_convo)
    assert any(m["role"] == "user" and "schema" in m["content"].lower() for m in repair_convo)
    # Tokens and hashes accumulate across the repair attempt.
    assert result.tokens_in == 300
    assert result.tokens_out == 150
    assert result.verification_metadata["prompt_hashes"] == ["h-1", "h-2", "h-3"]


def test_hunter_malformed_twice_falls_back_to_needs_verify():
    """Exhausting the repair budget falls back exactly as before (recall-safe)."""
    llm = _StubLlm(["garbage", "still garbage"])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert len(llm.calls) == 2
    assert result.verification_metadata["reason"].startswith("hunter_schema_invalid:")
    assert result.tokens_in == 200


def test_hunter_valid_first_response_makes_no_repair_call():
    """A valid first response is byte-identical to prior behavior — one call."""
    llm = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert len(llm.calls) == 2  # hunter + skeptic, no repair
    assert result.tokens_in == 200
    assert result.verification_metadata["prompt_hashes"] == ["h-1", "h-2"]


def test_skeptic_malformed_then_valid_recovers_mitigation():
    """A repaired skeptic turn recovers the intended ruled_out verdict."""
    good_skeptic = (
        '{"mitigation_found":true,"mitigation_file":"src/auth.py","mitigation_line":10,'
        '"mitigation_snippet":"if not is_authenticated: abort(401)","reasoning":"auth gate"}'
    )
    llm = _StubLlm([_GOOD_HUNTER, "oops prose", good_skeptic])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "ruled_out"
    assert len(llm.calls) == 3


# --- The two chains are independently invokable ---------------------------------

def test_run_tp_reasoning_parses_exploit_chain_standalone():
    """The TP-reasoning chain can be driven on its own and parses its schema."""
    llm = _StubLlm([_GOOD_HUNTER])
    result = run_tp_reasoning(_FINDING, "1: code", None, llm=llm)
    assert len(llm.calls) == 1
    assert result.parsed is not None
    assert result.parsed.exploit_chain == "x reaches y"
    assert result.parsed.evidence[0]["file"] == "a.py"


def test_run_tp_reasoning_reports_schema_failure_standalone():
    """An unrepairable response surfaces as parsed=None + an error (no exception)."""
    llm = _StubLlm(["not json", "still not json"])
    result = run_tp_reasoning(_FINDING, "1: code", None, llm=llm)
    assert result.parsed is None
    assert result.error


def test_run_fp_detection_parses_mitigation_standalone():
    """The FP-detection chain can be driven on its own and parses its schema."""
    llm = _StubLlm([
        '{"mitigation_found":true,"mitigation_file":"src/auth.py","mitigation_line":10,'
        '"mitigation_snippet":"abort(401)","reasoning":"auth gate"}'
    ])
    result = run_fp_detection(_FINDING, "x reaches y", "1: code", llm=llm)
    assert len(llm.calls) == 1
    assert result.parsed is not None
    assert result.parsed.mitigation_found is True
    assert result.parsed.mitigation_file == "src/auth.py"


# --- Frontier escalation tier (dormant unless an escalation client is passed) ----

def test_tier_default_stamped_and_no_escalation_key_by_default():
    llm = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(finding=_FINDING, repo_root="/x", llm=llm, critic=lambda ev, root: ([], []))
    assert result.verification_metadata["tier"] == "default"
    assert "escalated" not in result.verification_metadata


def test_escalates_to_frontier_when_default_hunter_schema_fails():
    """Default can't produce a valid exploit chain -> the frontier tier retries."""
    default = _StubLlm(["garbage", "still garbage"])  # both hunter turns fail
    frontier = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=default, escalation_llm=frontier,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["tier"] == "frontier"
    assert len(default.calls) == 2   # exhausted default repair budget
    assert len(frontier.calls) == 2  # frontier hunter + skeptic
    # Tokens accumulate across BOTH tiers.
    assert result.tokens_in == 400


def test_no_escalation_when_default_hunter_succeeds():
    default = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    frontier = _StubLlm([_GOOD_HUNTER])  # should never be touched
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=default, escalation_llm=frontier,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.verification_metadata["tier"] == "default"
    assert len(frontier.calls) == 0


def test_escalation_that_also_fails_stays_needs_verify():
    default = _StubLlm(["garbage", "still garbage"])
    frontier = _StubLlm(["frontier garbage", "frontier garbage 2"])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=default, escalation_llm=frontier,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["reason"].startswith("hunter_schema_invalid:")
