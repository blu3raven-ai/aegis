"""Tests for runner.verification.agents.base — the investigator loop."""
from __future__ import annotations

from runner.verification.agents.base import AgentResult, investigate
from runner.verification.llm_client import LlmToolResponse, ToolCall
from runner.verification.tools.base import Tool, ToolRegistry


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self._model = "stub"
        self.call_count = 0

    def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1000):
        self.call_count += 1
        return self._r.pop(0)


def _final(content: str, tokens_in: int = 100, tokens_out: int = 50) -> LlmToolResponse:
    return LlmToolResponse(
        content=content,
        tool_calls=[],
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        prompt_hash=f"h-{content[:5]}",
    )


def _tool_turn(*calls) -> LlmToolResponse:
    return LlmToolResponse(
        content="",
        tool_calls=list(calls),
        tokens_in=100,
        tokens_out=20,
        prompt_hash="h-tools",
    )


def _echo_tool() -> Tool:
    return Tool(
        name="echo",
        description="echoes",
        parameters={"type": "object", "properties": {"msg": {"type": "string"}}},
        handler=lambda args: f"echoed: {args.get('msg', '')}",
    )


# ---------------------------------------------------------------------------
# Terminal control flow
# ---------------------------------------------------------------------------


def test_immediate_final_answer_returns_completed():
    llm = _StubLlm([_final("done")])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
    )
    assert result.final_message == "done"
    assert result.stopped_reason == "completed"
    assert result.turns == 1
    assert result.tool_calls == []
    assert result.tokens_in == 100
    assert result.tokens_out == 50


def test_tool_call_then_final_executes_tool_and_returns_completed():
    llm = _StubLlm([
        _tool_turn(ToolCall(id="c1", name="echo", arguments={"msg": "hi"})),
        _final("here is the result"),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
    )
    assert result.stopped_reason == "completed"
    assert result.final_message == "here is the result"
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0].result == "echoed: hi"


def test_multi_step_tool_use_loops_correctly():
    llm = _StubLlm([
        _tool_turn(ToolCall(id="c1", name="echo", arguments={"msg": "one"})),
        _tool_turn(ToolCall(id="c2", name="echo", arguments={"msg": "two"})),
        _final("done"),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
    )
    assert result.stopped_reason == "completed"
    assert [r.arguments["msg"] for r in result.tool_calls] == ["one", "two"]
    assert result.turns == 3


def test_parallel_tool_calls_in_one_turn_all_executed():
    llm = _StubLlm([
        _tool_turn(
            ToolCall(id="c1", name="echo", arguments={"msg": "a"}),
            ToolCall(id="c2", name="echo", arguments={"msg": "b"}),
        ),
        _final("ok"),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
    )
    assert len(result.tool_calls) == 2


# ---------------------------------------------------------------------------
# Caps and stop reasons
# ---------------------------------------------------------------------------


def test_max_turns_cap_stops_with_reason():
    # Endless tool-turn stream
    responses = [_tool_turn(ToolCall(id=f"c{i}", name="echo", arguments={})) for i in range(20)]
    llm = _StubLlm(responses)
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
        max_turns=3,
    )
    assert result.stopped_reason == "max_turns"
    assert result.turns == 3


def test_llm_error_returns_error_reason_not_raise():
    class _Boomer:
        _model = "x"

        def chat_with_tools(self, *a, **kw):
            raise RuntimeError("transport down")

    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=_Boomer(),
    )
    assert result.stopped_reason == "llm_error"
    assert "llm error" in result.final_message


def test_budget_exhausted_stops_with_budget_reason():
    class _Exhausted:
        def allow(self):
            return False

        def record(self, **kwargs):
            pass

    llm = _StubLlm([_final("never reached")])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
        budget=_Exhausted(),
    )
    assert result.stopped_reason == "budget"
    assert llm.call_count == 0


def test_unknown_tool_call_recorded_not_raised():
    llm = _StubLlm([
        _tool_turn(ToolCall(id="c1", name="not_a_real_tool", arguments={})),
        _final("recovered"),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
    )
    assert result.stopped_reason == "completed"
    assert result.tool_calls[0].error and "unknown tool" in result.tool_calls[0].error
