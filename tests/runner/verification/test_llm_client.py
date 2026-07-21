"""LLM client (OpenAI-compatible HTTP) tests."""
from __future__ import annotations

import httpx
import pytest

from runner.verification.llm_client import (
    LlmAuthError,
    LlmClient,
    LlmRateLimitedError,
)


def _ok(content: str, tokens_in: int = 10, tokens_out: int = 5) -> httpx.Response:
    return httpx.Response(200, json={
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": {"prompt_tokens": tokens_in, "completion_tokens": tokens_out},
    })


def test_chat_returns_content_and_token_counts():
    def handler(req):
        return _ok("hello back", tokens_in=42, tokens_out=7)
    client = LlmClient(
        api_key="sk-test", api_base_url="https://api.example.ai/v1", model="m",
        transport=httpx.MockTransport(handler),
    )
    resp = client.chat([{"role": "user", "content": "hello"}])
    assert resp.content == "hello back"
    assert resp.tokens_in == 42
    assert resp.tokens_out == 7


def test_chat_raises_on_auth_failure():
    def handler(req):
        return httpx.Response(401, json={"error": "bad key"})
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(LlmAuthError):
        client.chat([{"role": "user", "content": "x"}])


def test_chat_retries_on_rate_limit_then_raises(monkeypatch):
    # A persistent 429 backs off (honoring Retry-After, capped) across the full
    # attempt budget, then surfaces LlmRateLimitedError rather than failing the
    # finding on the first 429.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return httpx.Response(429, headers={"Retry-After": "30"})

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(LlmRateLimitedError) as exc_info:
        client.chat([{"role": "user", "content": "x"}])
    assert exc_info.value.retry_after_seconds == 30
    assert calls["n"] == 4  # 1 initial + 3 retries


def test_chat_retries_on_rate_limit_then_succeeds(monkeypatch):
    # A transient 429 that clears is retried, not surfaced.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "1"})
        return _ok('{"a": 1}')

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def test_chat_strips_markdown_fences_from_content():
    # Self-hostable models routinely wrap JSON in ```json fences despite the
    # "raw JSON only" instruction. chat() must strip them so callers parsing
    # resp.content don't fail and burn a repair round-trip on every call.
    fenced = '```json\n{"exploit_chain": "x", "evidence": []}\n```'
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(lambda r: _ok(fenced)))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert resp.content == '{"exploit_chain": "x", "evidence": []}'


def test_chat_leaves_unfenced_content_untouched():
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(lambda r: _ok('{"a": 1}')))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert resp.content == '{"a": 1}'


def test_chat_retries_on_empty_content_then_succeeds(monkeypatch):
    # Under concurrent load the model can return 200 with empty content — a
    # transient overload window. chat() must back off and retry rather than
    # accept the empty response and force a schema-invalid verdict.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return _ok('{"a": 1}' if calls["n"] > 1 else "")

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def test_chat_returns_empty_after_retries_exhaust(monkeypatch):
    # If empty content persists, chat() returns the empty response so
    # chat_json's repair / needs_verify fallback applies (not a hard crash).
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(lambda r: _ok("")))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert resp.content == ""


def test_chat_retries_on_timeout_then_succeeds(monkeypatch):
    # A slow endpoint under load raises ReadTimeout. chat() must back off and
    # retry rather than surfacing as a hard llm_error that leaves the finding
    # unverified.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ReadTimeout("slow", request=req)
        return _ok('{"a": 1}')

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def test_chat_raises_transient_after_timeout_retries_exhaust(monkeypatch):
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    client = LlmClient(
        "k", "https://x/v1", "m",
        transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r))),
    )
    from runner.verification.llm_client import LlmTransientError
    with pytest.raises(LlmTransientError):
        client.chat([{"role": "user", "content": "x"}])


def test_chat_retries_on_connection_error_then_succeeds(monkeypatch):
    # A connection blip (refused / DNS / reset) is transient; retry before
    # leaving the finding unverified.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("refused", request=req)
        return _ok('{"a": 1}')

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def test_chat_retries_on_non_json_body_then_succeeds(monkeypatch):
    # A proxy/load balancer can return a 200 with an HTML error body; resp.json()
    # raises ValueError. Retry before failing the finding.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, text="<html>502 Bad Gateway</html>")
        return _ok('{"a": 1}')

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def test_chat_retries_on_malformed_choices_then_succeeds(monkeypatch):
    # Valid JSON but missing the choices shape; retry before surfacing.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(200, json={"error": "overloaded"})
        return _ok('{"a": 1}')

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat([{"role": "user", "content": "x"}])
    assert calls["n"] == 2
    assert resp.content == '{"a": 1}'


def _ok_tool_call(func_name: str = "grep") -> httpx.Response:
    # A normal tool-calling turn: empty content alongside a tool_calls array.
    return httpx.Response(200, json={
        "choices": [{"message": {
            "role": "assistant",
            "content": "",
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": func_name, "arguments": "{}"},
            }],
        }}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    })


def test_chat_with_tools_retries_transient_then_succeeds(monkeypatch):
    # The investigator loop uses chat_with_tools; a 5xx / 429 / connection blip
    # must retry rather than aborting the whole investigation on the first hit.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503)
        if calls["n"] == 2:
            raise httpx.ConnectError("refused", request=req)
        return _ok_tool_call()

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat_with_tools([{"role": "user", "content": "x"}], tools=[])
    assert calls["n"] == 3
    assert len(resp.tool_calls) == 1
    assert resp.tool_calls[0].name == "grep"


def test_chat_with_tools_empty_content_not_retried(monkeypatch):
    # Empty content is the NORMAL shape for a tool-calling turn (it rides with
    # tool_calls); chat_with_tools must NOT retry it as a stall.
    monkeypatch.setattr("runner.verification.llm_client.time.sleep", lambda _s: None)
    calls = {"n": 0}

    def handler(req):
        calls["n"] += 1
        return _ok_tool_call()

    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    resp = client.chat_with_tools([{"role": "user", "content": "x"}], tools=[])
    assert calls["n"] == 1  # no retry on the empty-content tool turn
    assert len(resp.tool_calls) == 1
