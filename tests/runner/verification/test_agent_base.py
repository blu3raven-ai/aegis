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


def test_max_turns_cap_forces_final_answer():
    # Model keeps calling tools through every turn, then the forcing call
    # (tools disabled) makes it commit a final answer instead of discarding it.
    responses = [
        _tool_turn(ToolCall(id=f"c{i}", name="echo", arguments={})) for i in range(3)
    ]
    responses.append(_final("forced verdict json", tokens_in=10, tokens_out=5))
    llm = _StubLlm(responses)
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys",
        user_task="ask",
        tools=reg,
        llm=llm,
        max_turns=3,
    )
    assert result.stopped_reason == "forced_final"
    assert result.final_message == "forced verdict json"
    assert result.turns == 3
    assert llm.call_count == 4  # 3 tool turns + 1 forcing turn


def test_soft_conclude_nudge_injected_once_when_half_spent():
    # Model keeps calling tools; once half the turns are spent it must be nudged
    # once to conclude, and only once (no repeated nudges bloating context).
    seen_msgs = []

    class _RecordingLlm:
        _model = "rec"

        def __init__(self):
            self.n = 0

        def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1000):
            self.n += 1
            seen_msgs.append([m.get("content") for m in messages if m["role"] == "user"])
            if self.n <= 5:
                return _tool_turn(ToolCall(id=f"c{self.n}", name="echo", arguments={"msg": str(self.n)}))
            return _final("done")

    llm = _RecordingLlm()
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys", user_task="ask", tools=reg, llm=llm, max_turns=8,
    )
    # soft_conclude_at defaults to max_turns//2 = 4; the nudge should appear in
    # the user messages exactly once across the whole run.
    from runner.verification.agents.base import _SOFT_CONCLUDE_DIRECTIVE
    nudge_appearances = sum(
        1 for msgs in seen_msgs if any(_SOFT_CONCLUDE_DIRECTIVE == m for m in msgs)
    )
    # Present on every call after injection, but injected only once.
    assert nudge_appearances >= 1
    injections = sum(
        _SOFT_CONCLUDE_DIRECTIVE in (seen_msgs[i] or [])
        and _SOFT_CONCLUDE_DIRECTIVE not in (seen_msgs[i - 1] or [])
        for i in range(1, len(seen_msgs))
    )
    assert injections == 1
    assert result.stopped_reason == "completed"


def test_prose_only_completion_is_rejected_and_forced():
    # Model stops calling tools but returns reasoning prose with no JSON. With a
    # JSON-aware is_final, that non-answer must not be accepted — it forces a
    # tool-free answer instead.
    import json as _json
    llm = _StubLlm([
        _final("Here is my reasoning, but no json object yet."),
        _final(_json.dumps({"exploit_chain": "x"})),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys", user_task="ask", tools=reg, llm=llm, max_turns=8,
        is_final=lambda c: "{" in c and "}" in c,
    )
    assert result.stopped_reason == "forced_final"
    assert "{" in result.final_message
    assert llm.call_count == 2  # non-answer turn + forcing turn


def test_default_is_final_accepts_any_nonempty_content():
    llm = _StubLlm([_final("plain answer, no json")])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=llm)
    assert result.stopped_reason == "completed"
    assert result.final_message == "plain answer, no json"


def test_stuck_repeating_same_call_breaks_early_and_forces_answer():
    # Model issues the identical tool call every turn (no new information).
    # After the stall limit it must be cut off and forced, well before max_turns.
    same_call = ToolCall(id="c", name="echo", arguments={"msg": "loop"})
    # 3 identical tool turns then the forcing call (4th) is answered.
    responses = [_tool_turn(same_call) for _ in range(3)]
    responses.append(_final("forced out of the loop"))
    llm = _StubLlm(responses)
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys", user_task="ask", tools=reg, llm=llm, max_turns=8,
    )
    assert result.stopped_reason == "forced_final"
    assert result.final_message == "forced out of the loop"
    # Turn 1's call is new info; turns 2 and 3 are pure repeats, so the 2nd
    # stalled turn forces the answer at turn 3 — nowhere near the 8-turn cap.
    assert result.turns == 3
    assert llm.call_count == 4


def test_distinct_calls_do_not_trip_stuck_detector():
    llm = _StubLlm([
        _tool_turn(ToolCall(id="c1", name="echo", arguments={"msg": "a"})),
        _tool_turn(ToolCall(id="c2", name="echo", arguments={"msg": "b"})),
        _tool_turn(ToolCall(id="c3", name="echo", arguments={"msg": "c"})),
        _final("done properly"),
    ])
    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys", user_task="ask", tools=reg, llm=llm, max_turns=8,
    )
    assert result.stopped_reason == "completed"
    assert result.final_message == "done properly"


def test_forced_final_llm_error_returns_error_reason():
    class _FailOnForce:
        _model = "x"

        def __init__(self):
            self.n = 0

        def chat_with_tools(self, messages, *, tools, temperature=0.0, max_tokens=1000):
            self.n += 1
            if tools:  # tool turns keep the loop going
                return _tool_turn(ToolCall(id=f"c{self.n}", name="echo", arguments={}))
            raise RuntimeError("transport down")  # forcing turn fails

    reg = ToolRegistry([_echo_tool()])
    result = investigate(
        system_prompt="sys", user_task="ask", tools=reg, llm=_FailOnForce(), max_turns=2,
    )
    assert result.stopped_reason == "llm_error"


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
