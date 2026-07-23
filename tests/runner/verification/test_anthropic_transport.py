"""Transport harness: the Anthropic Messages API path with prompt caching.

Drives the real ``LlmClient`` + ``investigate`` through ``httpx.MockTransport``
so the anthropic wire shape (tool spec translation, tool_use / tool_result
correlation, cache breakpoints, usage folding) is exercised end to end and the
resulting ``AgentResult`` is asserted equal to the chat transport's.
"""
from __future__ import annotations

import json

import httpx
import pytest

from runner.verification.agents.base import investigate
from runner.verification.llm_client import LlmClient, LlmError
from runner.verification.tools.base import Tool, ToolRegistry

_IS_JSON = lambda c: "{" in c and "}" in c  # noqa: E731

_ANTHROPIC_BASE = "https://x/anthropic/v1"


def _echo_tool() -> Tool:
    return Tool(
        name="echo",
        description="echoes",
        parameters={"type": "object", "properties": {"msg": {"type": "string"}}},
        handler=lambda args: f"echoed: {args.get('msg', '')}",
    )


# --- chat wire shapes (the equality baseline) ------------------------------

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


# --- anthropic wire shapes -------------------------------------------------

def _anthropic_tool(cid, name, inp):
    return httpx.Response(200, json={
        "id": "msg_tool",
        "content": [{"type": "tool_use", "id": cid, "name": name, "input": inp}],
        "stop_reason": "tool_use",
        "usage": {"input_tokens": 100, "output_tokens": 20},
    })


def _anthropic_final(text):
    return httpx.Response(200, json={
        "id": "msg_final",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 100, "output_tokens": 50},
    })


def _chat_handler(steps):
    queue = list(steps)

    def handler(req):
        step = queue.pop(0)
        if step[0] == "tool":
            _, cid, name, args = step
            return _chat_tool(cid, name, args)
        return _chat_final(step[1])

    return handler


def _anthropic_handler(steps, sink=None):
    """Serve one scripted anthropic step per request, recording bodies + headers."""
    queue = list(steps)

    def handler(req):
        if sink is not None:
            sink.append({
                "path": req.url.path,
                "headers": dict(req.headers),
                "body": json.loads(req.content),
            })
        step = queue.pop(0)
        if step[0] == "tool":
            _, cid, name, args = step
            return _anthropic_tool(cid, name, args)
        return _anthropic_final(step[1])

    return handler


def _make_client(handler, monkeypatch, *, transport="anthropic", base=_ANTHROPIC_BASE):
    monkeypatch.setenv("LLM_TRANSPORT", transport)
    return LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(handler),
        anthropic_base_url=base,
    )


def test_anthropic_matches_chat_result(monkeypatch):
    # The same scripted model outputs must yield the same AgentResult whether the
    # anthropic or chat transport carried the turns.
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"verdict":"ok"}')]
    reg = ToolRegistry([_echo_tool()])

    c1 = _make_client(_anthropic_handler(script), monkeypatch)
    r_ant = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=c1, is_final=_IS_JSON)

    monkeypatch.setenv("LLM_TRANSPORT", "chat")
    c2 = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(_chat_handler(script)))
    r_chat = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=c2, is_final=_IS_JSON)

    assert r_ant.final_message == r_chat.final_message == '{"verdict":"ok"}'
    assert r_ant.stopped_reason == r_chat.stopped_reason == "completed"
    assert r_ant.turns == r_chat.turns == 2
    assert r_ant.tokens_in == r_chat.tokens_in == 200
    assert r_ant.tokens_out == r_chat.tokens_out == 70
    assert [(t.name, t.arguments, t.result) for t in r_ant.tool_calls] == \
           [(t.name, t.arguments, t.result) for t in r_chat.tool_calls]


def test_anthropic_headers_path_and_tool_schema(monkeypatch):
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"a":1}')]
    reg = ToolRegistry([_echo_tool()])
    sink: list[dict] = []

    client = _make_client(_anthropic_handler(script, sink), monkeypatch)
    investigate(system_prompt="sys", user_task="ask", tools=reg, llm=client, is_final=_IS_JSON)

    first = sink[0]
    assert first["path"].endswith("/messages")
    assert first["headers"].get("x-api-key") == "k"
    assert first["headers"].get("anthropic-version") == "2023-06-01"

    # Tools travel in the anthropic input_schema shape, not the OpenAI parameters shape.
    tools = first["body"]["tools"]
    assert tools == [{
        "name": "echo",
        "description": "echoes",
        "input_schema": {"type": "object", "properties": {"msg": {"type": "string"}}},
    }]


def test_anthropic_tool_result_correlates_tool_use_id(monkeypatch):
    script = [("tool", "call-xyz", "echo", {"msg": "hi"}), ("final", '{"a":1}')]
    reg = ToolRegistry([_echo_tool()])
    sink: list[dict] = []

    client = _make_client(_anthropic_handler(script, sink), monkeypatch)
    investigate(system_prompt="sys", user_task="ask", tools=reg, llm=client, is_final=_IS_JSON)

    # The 2nd request replays the tool call as an assistant tool_use block, then a
    # user tool_result block that references the same id.
    second_msgs = sink[1]["body"]["messages"]
    assistant = [m for m in second_msgs if m["role"] == "assistant"][-1]
    assert any(b["type"] == "tool_use" and b["id"] == "call-xyz" for b in assistant["content"])
    tool_result_msg = second_msgs[-1]
    result_block = tool_result_msg["content"][0]
    assert result_block["type"] == "tool_result"
    assert result_block["tool_use_id"] == "call-xyz"
    assert result_block["content"] == "echoed: hi"


def test_anthropic_cache_breakpoints_system_and_moving(monkeypatch):
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"a":1}')]
    reg = ToolRegistry([_echo_tool()])
    sink: list[dict] = []

    client = _make_client(_anthropic_handler(script, sink), monkeypatch)
    investigate(system_prompt="sys", user_task="ask", tools=reg, llm=client, is_final=_IS_JSON)

    for req in sink:
        body = req["body"]
        # System breakpoint (static).
        assert body["system"][0]["cache_control"] == {"type": "ephemeral"}
        # Moving breakpoint on the last content block of the last message.
        assert body["messages"][-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}
        # Never more than the two breakpoints (system + one moving).
        marks = json.dumps(body).count('"cache_control"')
        assert marks == 2


def test_anthropic_requires_base_url(monkeypatch):
    # Selecting the transport without a base URL is a misconfiguration, not a
    # fallback: construction must fail loudly and name the env var.
    monkeypatch.setenv("LLM_TRANSPORT", "anthropic")
    with pytest.raises(LlmError, match="LLM_ANTHROPIC_BASE_URL"):
        LlmClient("k", "https://x/v1", "m")
