"""Transport harness: responses API with chat-completions fallback.

Drives the real ``LlmClient`` + ``investigate`` through ``httpx.MockTransport``
so both the responses and chat wire shapes, capability detection, and the
delta-only responses turns are exercised end to end.
"""
from __future__ import annotations

import json

import httpx

from runner.verification.agents.base import investigate
from runner.verification.llm_client import LlmClient
from runner.verification.tools.base import Tool, ToolRegistry

_IS_JSON = lambda c: "{" in c and "}" in c  # noqa: E731


def _echo_tool() -> Tool:
    return Tool(
        name="echo",
        description="echoes",
        parameters={"type": "object", "properties": {"msg": {"type": "string"}}},
        handler=lambda args: f"echoed: {args.get('msg', '')}",
    )


def _chat_tool(cid, name, args):
    return httpx.Response(200, json={
        "choices": [{"message": {
            "role": "assistant", "content": "",
            "tool_calls": [{"id": cid, "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)}}],
        }}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20},
    })


def _chat_final(text):
    return httpx.Response(200, json={
        "choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 50},
    })


def _resp_tool(rid, cid, name, args):
    return httpx.Response(200, json={
        "id": rid,
        "output": [{"type": "function_call", "call_id": cid, "name": name,
                    "arguments": json.dumps(args)}],
        "usage": {"input_tokens": 100, "output_tokens": 20},
    })


def _resp_final(rid, text):
    return httpx.Response(200, json={
        "id": rid,
        "output": [{"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": text}]}],
        "usage": {"input_tokens": 100, "output_tokens": 50},
    })


def _script_handler(steps):
    """Serve one scripted step per request in whichever wire shape was asked.

    A step is ("tool", call_id, name, args) or ("final", text). The same script
    yields matching token counts on both endpoints so the two transports can be
    asserted equal.
    """
    queue = list(steps)
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        step = queue.pop(0)
        rid = f"resp_{state['n']}"
        on_responses = req.url.path.endswith("/responses")
        if step[0] == "tool":
            _, cid, name, args = step
            return _resp_tool(rid, cid, name, args) if on_responses else _chat_tool(cid, name, args)
        return _resp_final(rid, step[1]) if on_responses else _chat_final(step[1])

    return handler


def test_chat_and_responses_produce_identical_result(monkeypatch):
    # Same scripted model outputs must yield the same AgentResult regardless of
    # which transport carried the turns; the harness is a transport swap only.
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"verdict":"ok"}')]
    reg = ToolRegistry([_echo_tool()])

    monkeypatch.setenv("LLM_TRANSPORT", "responses")
    c1 = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(_script_handler(script)))
    r_resp = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=c1, is_final=_IS_JSON)

    monkeypatch.setenv("LLM_TRANSPORT", "chat")
    c2 = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(_script_handler(script)))
    r_chat = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=c2, is_final=_IS_JSON)

    assert r_resp.final_message == r_chat.final_message == '{"verdict":"ok"}'
    assert r_resp.stopped_reason == r_chat.stopped_reason == "completed"
    assert r_resp.turns == r_chat.turns == 2
    assert r_resp.tokens_in == r_chat.tokens_in == 200
    assert r_resp.tokens_out == r_chat.tokens_out == 70
    assert [(t.name, t.arguments, t.result) for t in r_resp.tool_calls] == \
           [(t.name, t.arguments, t.result) for t in r_chat.tool_calls]


def test_responses_404_falls_back_permanently_and_stops_probing(monkeypatch):
    # An endpoint that 404s on /responses is used once, flips to chat for good,
    # and never probes /responses again on later conversations.
    monkeypatch.setenv("LLM_TRANSPORT", "auto")
    paths: list[str] = []

    def handler(req):
        paths.append(req.url.path)
        if req.url.path.endswith("/responses"):
            return httpx.Response(404, json={"error": "unknown route"})
        return _chat_final('{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    r1 = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r1.stopped_reason == "completed"
    assert client._supports_responses is False

    paths.clear()
    r2 = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r2.stopped_reason == "completed"
    assert paths and all(not p.endswith("/responses") for p in paths)


def test_responses_200_uses_responses_and_caches(monkeypatch):
    monkeypatch.setenv("LLM_TRANSPORT", "auto")
    paths: list[str] = []

    def handler(req):
        paths.append(req.url.path)
        assert req.url.path.endswith("/responses")
        return _resp_final("r1", '{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert client._supports_responses is True
    assert all(p.endswith("/responses") for p in paths)


def test_responses_transient_5xx_does_not_permanently_fall_back(monkeypatch):
    # A 503 on /responses is a transient failure: it must retry the same route,
    # not treat the endpoint as unsupported and defect to chat.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    monkeypatch.setenv("LLM_TRANSPORT", "auto")
    calls = {"responses": 0}

    def handler(req):
        if req.url.path.endswith("/responses"):
            calls["responses"] += 1
            if calls["responses"] == 1:
                return httpx.Response(503)
            return _resp_final("r1", '{"a":1}')
        raise AssertionError("must not fall back to chat on a transient 5xx")

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert client._supports_responses is True
    assert calls["responses"] == 2  # retried through the transient, not fell back


def test_responses_sends_only_delta_on_second_turn(monkeypatch):
    # The token win: turn 2 must carry previous_response_id + only the new tool
    # output, never the prior system prompt / user task / history.
    monkeypatch.setenv("LLM_TRANSPORT", "responses")
    bodies: list[dict] = []

    def handler(req):
        bodies.append(json.loads(req.content))
        if len(bodies) == 1:
            return _resp_tool("resp_1", "c1", "echo", {})
        return _resp_final("resp_2", '{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    investigate(system_prompt="SYSPROMPT", user_task="USERTASK", tools=reg, llm=client, is_final=_IS_JSON)

    first, second = bodies[0], bodies[1]
    assert "previous_response_id" not in first
    assert any(i.get("role") == "system" for i in first["input"])
    assert any(i.get("role") == "user" for i in first["input"])

    assert second["previous_response_id"] == "resp_1"
    assert all(i.get("type") == "function_call_output" for i in second["input"])
    dumped = json.dumps(second["input"])
    assert "SYSPROMPT" not in dumped and "USERTASK" not in dumped


def test_transport_chat_forces_chat_and_never_probes(monkeypatch):
    monkeypatch.setenv("LLM_TRANSPORT", "chat")
    paths: list[str] = []

    def handler(req):
        paths.append(req.url.path)
        return _chat_final('{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert all(p.endswith("/chat/completions") for p in paths)
    assert client._supports_responses is None  # forced chat never probes /responses
