"""Verification pipeline tests."""
from __future__ import annotations

from runner.verification.llm_client import LlmToolResponse, ToolCall
from runner.verification.pipeline import (
    run_fp_detection,
    run_tp_reasoning,
    verify_finding,
)


class _StubLlm:
    """Scripts ``chat_with_tools`` so the investigator loop is driven directly.

    Each scripted response is a raw JSON string (returned as a final message
    with no tool call) or an ``LlmToolResponse`` used verbatim for a tool turn.
    """

    def __init__(self, responses):
        self._r = list(responses)
        self._model = "stub-model"
        self.calls = []

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        item = self._r.pop(0)
        if isinstance(item, LlmToolResponse):
            return item
        return LlmToolResponse(
            content=item, tool_calls=[], tokens_in=100, tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


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


def test_confirmed_finding_surfaces_cvss_distinctness_and_poc_from_hunter():
    # End-to-end proof that an LLM-shaped hunter response carrying the advisory
    # enrichment flows through the whole pipeline: the model CLASSIFIES the CVSS
    # base metrics and the score is computed deterministically here; distinctness
    # and the benign PoC ride along into verification_metadata.
    llm = _StubLlm([
        '{"exploit_chain":"x reaches y [R1]",'
        '"evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}],'
        '"cvss_metrics":{"AV":"L","AC":"L","PR":"N","UI":"R","S":"U","C":"H","I":"H","A":"H"},'
        '"distinctness":"Different sink than the known advisory.",'
        '"poc_script":"print(\'pwned\')","poc_filename":"poc.py","poc_language":"python"}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    meta = result.verification_metadata
    assert meta["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
    assert meta["cvss_score"] == 7.8
    assert meta["distinctness"] == "Different sink than the known advisory."
    assert meta["poc_script"] == "print('pwned')"
    assert meta["poc_filename"] == "poc.py"


def test_non_confirmed_finding_omits_cvss_and_poc():
    # A non-confirmed verdict must not carry the advisory enrichment: surfacing
    # a CVSS score or PoC on an unconfirmed chain would overstate confidence.
    llm = _StubLlm([
        '{"exploit_chain":"x [R1]",'
        '"evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}],'
        '"cvss_metrics":{"AV":"L","AC":"L","PR":"N","UI":"R","S":"U","C":"H","I":"H","A":"H"},'
        '"poc_script":"print(\'pwned\')"}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: (["a.py:1"], []),  # unverified citation -> needs_verify
    )
    assert result.verdict == "needs_verify"
    assert "cvss_score" not in result.verification_metadata
    assert "poc_script" not in result.verification_metadata


def test_non_confirmed_finding_omits_reproduction():
    # needs_verify (unverified citation) must not carry repro steps: that would
    # overstate confidence in an unconfirmed chain.
    llm = _StubLlm([
        '{"exploit_chain":"x [R1]","evidence":[{"file":"a.py","line":1,"snippet":"x","kind":"source"}],'
        '"reproduction":"do the thing"}',
        '{"mitigation_found":false,"reasoning":"none"}',
    ])
    result = verify_finding(
        finding={"file": "a.py", "line": 1, "tool": "sast", "rule": "x", "severity": "high"},
        repo_root="/x", llm=llm,
        critic=lambda ev, root: (["a.py:1"], []),  # unverified citation -> needs_verify
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


def _tool_turn(name: str, **arguments) -> LlmToolResponse:
    return LlmToolResponse(
        content="", tool_calls=[ToolCall(id="c1", name=name, arguments=arguments)],
        tokens_in=100, tokens_out=50, prompt_hash="h-tool",
    )


def test_hunter_calls_tool_then_answers_yields_confirmed():
    """The hunter investigates (a tool call) then answers; the tool is
    dispatched and the final JSON parses into a confirmed verdict."""
    llm = _StubLlm([_tool_turn("grep_repo", pattern="x"), _GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    # Hunter took two turns (tool call + answer); the skeptic took one.
    assert len(llm.calls) == 3


def test_hunter_unparseable_final_falls_back_to_needs_verify():
    """An unparseable final message yields parsed=None -> needs_verify (recall-safe)."""
    # Prose with no JSON is rejected, so the loop spends a forcing turn; when
    # that also yields no JSON the finding still falls back to needs_verify.
    llm = _StubLlm(["garbage", "still no json"])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert len(llm.calls) == 2  # hunter turn + forcing turn
    assert result.verification_metadata["reason"].startswith("hunter_schema_invalid:")
    assert result.tokens_in == 200


def test_hunter_valid_first_response_makes_no_extra_call():
    """A valid first answer costs exactly one call per chain."""
    llm = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert len(llm.calls) == 2  # hunter + skeptic
    assert result.tokens_in == 200
    assert result.verification_metadata["prompt_hashes"] == []


def test_skeptic_unparseable_falls_back_to_no_mitigation():
    """An unparseable skeptic answer defaults to no mitigation -> confirmed."""
    # Skeptic prose with no JSON forces a retry; still no JSON defaults to no
    # mitigation -> confirmed.
    llm = _StubLlm([_GOOD_HUNTER, "oops prose not json", "still not json"])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=llm,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert len(llm.calls) == 3  # hunter + skeptic + skeptic forcing turn


# --- The two chains are independently invokable ---------------------------------

def test_run_tp_reasoning_parses_exploit_chain_standalone():
    """The TP-reasoning chain can be driven on its own and parses its schema."""
    llm = _StubLlm([_GOOD_HUNTER])
    result = run_tp_reasoning(_FINDING, "1: code", None, llm=llm, repo_root="/x")
    assert len(llm.calls) == 1
    assert result.parsed is not None
    assert result.parsed.exploit_chain == "x reaches y"
    assert result.parsed.evidence[0]["file"] == "a.py"


def test_run_tp_reasoning_reports_schema_failure_standalone():
    """An unparseable response surfaces as parsed=None + an error (no exception)."""
    llm = _StubLlm(["not json"])
    result = run_tp_reasoning(_FINDING, "1: code", None, llm=llm, repo_root="/x")
    assert result.parsed is None
    assert result.error


def test_run_fp_detection_parses_mitigation_standalone():
    """The FP-detection chain can be driven on its own and parses its schema."""
    llm = _StubLlm([
        '{"mitigation_found":true,"mitigation_file":"src/auth.py","mitigation_line":10,'
        '"mitigation_snippet":"abort(401)","reasoning":"auth gate"}'
    ])
    result = run_fp_detection(_FINDING, "x reaches y", "1: code", llm=llm, repo_root="/x")
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
    default = _StubLlm(["garbage", "still garbage"])  # default hunter fails even after forcing
    frontier = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=default, escalation_llm=frontier,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "confirmed"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["tier"] == "frontier"
    assert len(default.calls) == 2   # default hunter turn + forcing turn
    assert len(frontier.calls) == 2  # frontier hunter + skeptic (both valid, no forcing)
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
    default = _StubLlm(["garbage"])
    frontier = _StubLlm(["frontier garbage"])
    result = verify_finding(
        finding=_FINDING, repo_root="/x", llm=default, escalation_llm=frontier,
        critic=lambda ev, root: ([], []),
    )
    assert result.verdict == "needs_verify"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["reason"].startswith("hunter_schema_invalid:")
