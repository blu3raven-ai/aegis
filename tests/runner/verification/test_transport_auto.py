"""Transport harness: LLM_TRANSPORT=auto precedence and degrade-to-chat.

Drives the real ``LlmClient`` + ``investigate`` through ``httpx.MockTransport``
so the auto precedence (anthropic when a base URL is set, else responses, always
falling back to chat) and the permanent degrade-to-chat on an unsupported signal
are exercised end to end.
"""
from __future__ import annotations

import json

import httpx

from runner.verification.agents.base import investigate
from runner.verification.llm_client import LlmClient
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


def _chat_script(steps):
    """Serve one scripted chat step per /chat/completions request."""
    queue = list(steps)

    def take():
        step = queue.pop(0)
        if step[0] == "tool":
            _, cid, name, args = step
            return _chat_tool(cid, name, args)
        return _chat_final(step[1])

    return take


def test_auto_prefers_anthropic_when_base_set(monkeypatch):
    # auto + anthropic base configured + healthy endpoint => anthropic transport.
    monkeypatch.setenv("LLM_TRANSPORT", "auto")
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"a":1}')]
    queue = list(script)
    paths: list[str] = []

    def handler(req):
        paths.append(req.url.path)
        step = queue.pop(0)
        if step[0] == "tool":
            _, cid, name, args = step
            return _anthropic_tool(cid, name, args)
        return _anthropic_final(step[1])

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(handler), anthropic_base_url=_ANTHROPIC_BASE,
    )
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert client._supports_anthropic is True
    assert paths and all(p.endswith("/messages") for p in paths)


def test_auto_anthropic_unsupported_degrades_to_chat(monkeypatch):
    # auto + anthropic base configured, but the endpoint 404s on /messages: the
    # conversation degrades to chat and produces the SAME AgentResult as a pure
    # chat run of the same script.
    script = [("tool", "c1", "echo", {"msg": "hi"}), ("final", '{"verdict":"ok"}')]

    monkeypatch.setenv("LLM_TRANSPORT", "auto")
    chat = _chat_script(script)

    def handler(req):
        if req.url.path.endswith("/messages"):
            return httpx.Response(404, json={"type": "error", "error": {"message": "unknown route"}})
        return chat()

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(handler), anthropic_base_url=_ANTHROPIC_BASE,
    )
    r_auto = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=client, is_final=_IS_JSON)
    assert client._supports_anthropic is False

    monkeypatch.setenv("LLM_TRANSPORT", "chat")
    c2 = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(_baseline(script)))
    r_chat = investigate(system_prompt="sys", user_task="ask", tools=reg, llm=c2, is_final=_IS_JSON)

    assert r_auto.final_message == r_chat.final_message == '{"verdict":"ok"}'
    assert r_auto.stopped_reason == r_chat.stopped_reason == "completed"
    assert r_auto.turns == r_chat.turns == 2
    assert r_auto.tokens_in == r_chat.tokens_in == 200
    assert r_auto.tokens_out == r_chat.tokens_out == 70
    assert [(t.name, t.arguments, t.result) for t in r_auto.tool_calls] == \
           [(t.name, t.arguments, t.result) for t in r_chat.tool_calls]


def _baseline(script):
    chat = _chat_script(script)

    def handler(req):
        assert req.url.path.endswith("/chat/completions")
        return chat()

    return handler


def test_auto_no_anthropic_base_uses_responses(monkeypatch):
    # auto without an anthropic base falls to the responses probe; a healthy
    # /responses endpoint is used and cached.
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
    assert client._supports_anthropic is None  # anthropic never attempted
    assert all(p.endswith("/responses") for p in paths)


def test_auto_no_anthropic_base_responses_404_degrades_to_chat(monkeypatch):
    # auto without an anthropic base: a /responses 404 flips the client to chat.
    monkeypatch.setenv("LLM_TRANSPORT", "auto")

    def handler(req):
        if req.url.path.endswith("/responses"):
            return httpx.Response(404, json={"error": "unknown route"})
        return _chat_final('{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert client._supports_responses is False


def test_explicit_anthropic_failure_degrades_to_chat(monkeypatch):
    # Explicit anthropic with a failing endpoint degrades to chat rather than
    # hard-failing, so a single misconfiguration does not nuke every finding.
    monkeypatch.setenv("LLM_TRANSPORT", "anthropic")

    def handler(req):
        if req.url.path.endswith("/messages"):
            return httpx.Response(404, json={"type": "error", "error": {"message": "no such route"}})
        return _chat_final('{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(handler), anthropic_base_url=_ANTHROPIC_BASE,
    )
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert "{" in r.final_message
    assert client._supports_anthropic is False


def test_auto_anthropic_400_shape_degrades_to_chat(monkeypatch):
    # A 400 that names a bad request shape (route exists but our body is rejected)
    # is treated as an unsupported signal on the anthropic path too.
    monkeypatch.setenv("LLM_TRANSPORT", "auto")

    def handler(req):
        if req.url.path.endswith("/messages"):
            return httpx.Response(400, json={"type": "error", "error": {
                "type": "invalid_request_error", "message": "bad shape"}})
        return _chat_final('{"a":1}')

    reg = ToolRegistry([_echo_tool()])
    client = LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(handler), anthropic_base_url=_ANTHROPIC_BASE,
    )
    r = investigate(system_prompt="s", user_task="a", tools=reg, llm=client, is_final=_IS_JSON)
    assert r.stopped_reason == "completed"
    assert client._supports_anthropic is False
