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


def test_chat_raises_on_rate_limit_with_retry_after():
    def handler(req):
        return httpx.Response(429, headers={"Retry-After": "30"})
    client = LlmClient("k", "https://x/v1", "m", transport=httpx.MockTransport(handler))
    with pytest.raises(LlmRateLimitedError) as exc_info:
        client.chat([{"role": "user", "content": "x"}])
    assert exc_info.value.retry_after_seconds == 30
