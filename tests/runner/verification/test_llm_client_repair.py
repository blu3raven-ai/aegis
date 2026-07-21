"""Unit tests for LlmClient.chat_json's schema-repair loop."""
from __future__ import annotations

from runner.verification.llm_client import LlmClient, LlmResponse
from runner.verification.schemas.verdict import HunterResponse

_VALID = '{"exploit_chain":"x reaches y","evidence":[]}'


class _StubLlm(LlmClient):
    """Scripts ``chat`` so ``chat_json`` runs against a canned response sequence."""

    def __init__(self, responses):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub-model")
        self._r = list(responses)
        self.calls = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(list(messages))
        return LlmResponse(
            content=self._r.pop(0), tokens_in=10, tokens_out=5,
            prompt_hash=f"h-{len(self.calls)}",
        )


def test_chat_json_valid_first_response_is_single_call():
    llm = _StubLlm([_VALID])
    result = llm.chat_json([{"role": "user", "content": "go"}], HunterResponse)
    assert isinstance(result.parsed, HunterResponse)
    assert result.parsed.exploit_chain == "x reaches y"
    assert result.error is None
    assert len(llm.calls) == 1
    assert result.prompt_hashes == ["h-1"]
    assert result.tokens_in == 10
    assert result.tokens_out == 5


def test_chat_json_malformed_then_valid_repairs_and_recovers():
    llm = _StubLlm(["not json at all", _VALID])
    result = llm.chat_json([{"role": "user", "content": "go"}], HunterResponse)
    assert isinstance(result.parsed, HunterResponse)
    assert result.error is None
    assert len(llm.calls) == 2
    # Second call is the repair conversation: original + bad assistant + repair user.
    repair_convo = llm.calls[1]
    assert repair_convo[0] == {"role": "user", "content": "go"}
    assert repair_convo[1] == {"role": "assistant", "content": "not json at all"}
    assert repair_convo[2]["role"] == "user"
    assert "HunterResponse" in repair_convo[2]["content"]
    assert "schema" in repair_convo[2]["content"].lower()
    # Tokens and hashes accumulate across both attempts.
    assert result.tokens_in == 20
    assert result.tokens_out == 10
    assert result.prompt_hashes == ["h-1", "h-2"]


def test_chat_json_malformed_twice_returns_none_without_raising():
    llm = _StubLlm(["garbage", "still garbage"])
    result = llm.chat_json([{"role": "user", "content": "go"}], HunterResponse)
    assert result.parsed is None
    assert result.error  # carries the final validation error
    assert len(llm.calls) == 2
    assert result.prompt_hashes == ["h-1", "h-2"]
    assert result.tokens_in == 20


def test_chat_json_respects_max_repairs_zero():
    llm = _StubLlm(["garbage"])
    result = llm.chat_json(
        [{"role": "user", "content": "go"}], HunterResponse, max_repairs=0,
    )
    assert result.parsed is None
    assert len(llm.calls) == 1


class _TruncStubLlm(LlmClient):
    """Scripts ``chat`` with (content, truncated) pairs and records max_tokens."""

    def __init__(self, responses):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub-model")
        self._r = list(responses)
        self.calls = []
        self.max_tokens_seen = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(list(messages))
        self.max_tokens_seen.append(max_tokens)
        content, truncated = self._r.pop(0)
        return LlmResponse(
            content=content, tokens_in=10, tokens_out=5,
            prompt_hash=f"h-{len(self.calls)}", truncated=truncated,
        )


def test_chat_json_truncated_escalates_tokens_and_retries_original_prompt():
    # A truncated first response is retried on the ORIGINAL prompt (no repair
    # reprompt) with a larger token cap, and recovers when it completes.
    llm = _TruncStubLlm([('{"exploit_chain":"x rea', True), (_VALID, False)])
    result = llm.chat_json(
        [{"role": "user", "content": "go"}], HunterResponse, max_tokens=3000,
    )
    assert isinstance(result.parsed, HunterResponse)
    assert result.error is None
    assert len(llm.calls) == 2
    # Escalated cap on the retry.
    assert llm.max_tokens_seen == [3000, 8000]
    # Retry is the ORIGINAL prompt, not a repair conversation.
    assert llm.calls[1] == [{"role": "user", "content": "go"}]


def test_chat_json_truncation_escalation_is_capped():
    # Escalation never exceeds the ceiling even from a high starting cap.
    llm = _TruncStubLlm([("truncated…", True), (_VALID, False)])
    result = llm.chat_json(
        [{"role": "user", "content": "go"}], HunterResponse, max_tokens=5000,
    )
    assert isinstance(result.parsed, HunterResponse)
    assert llm.max_tokens_seen == [5000, 8000]  # min(5000*3, 8000)


def test_chat_json_schema_error_still_uses_repair_not_escalation():
    # A non-truncated malformed response keeps the repair-reprompt behavior and
    # does not escalate the token cap.
    llm = _TruncStubLlm([("not json", False), (_VALID, False)])
    result = llm.chat_json(
        [{"role": "user", "content": "go"}], HunterResponse, max_tokens=3000,
    )
    assert isinstance(result.parsed, HunterResponse)
    assert llm.max_tokens_seen == [3000, 3000]  # unchanged
    assert llm.calls[1][1] == {"role": "assistant", "content": "not json"}
    assert llm.calls[1][2]["role"] == "user"  # repair prompt present
