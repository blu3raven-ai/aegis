"""OpenAI-compatible chat-completions HTTP client.

Works against any OpenAI-style endpoint: OpenAI, Anthropic adapter,
Azure OpenAI, vLLM, LiteLLM, OpenRouter.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


class LlmError(Exception):
    pass


class LlmAuthError(LlmError):
    pass


class LlmRateLimitedError(LlmError):
    def __init__(self, retry_after_seconds: int | None = None) -> None:
        super().__init__("llm rate limited")
        self.retry_after_seconds = retry_after_seconds


class LlmTransientError(LlmError):
    pass


@dataclass
class LlmResponse:
    content: str
    tokens_in: int
    tokens_out: int
    prompt_hash: str


@dataclass
class ToolCall:
    """One tool-call request returned by the LLM."""

    id: str
    name: str
    arguments: dict


@dataclass
class LlmToolResponse:
    """Result of a chat that may include tool calls.

    ``content`` is the assistant's text (may be empty when only tool
    calls are emitted). ``tool_calls`` is empty for a terminal turn.
    """

    content: str
    tool_calls: list[ToolCall]
    tokens_in: int
    tokens_out: int
    prompt_hash: str


class LlmClient:
    def __init__(
        self, api_key: str, api_base_url: str, model: str,
        *, transport: httpx.BaseTransport | None = None, timeout: float = 60.0,
    ) -> None:
        self._api_key = api_key
        self._api_base_url = api_base_url.rstrip("/")
        self._model = model
        self._transport = transport
        self._timeout = timeout

    def chat(self, messages: list[dict], *, temperature: float = 0.0, max_tokens: int = 1024) -> LlmResponse:
        url = f"{self._api_base_url}/chat/completions"
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            resp = client.post(
                url, json=payload,
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            )

        if resp.status_code in (401, 403):
            raise LlmAuthError(f"llm auth failed: {resp.status_code}")
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "30")
            retry_after = int(ra) if ra.isdigit() else 30
            raise LlmRateLimitedError(retry_after_seconds=retry_after)
        if resp.status_code >= 500:
            raise LlmTransientError(f"llm 5xx: {resp.status_code}")
        if resp.status_code >= 400:
            raise LlmError(f"llm unexpected: {resp.status_code} {resp.text[:200]}")

        data = resp.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            raise LlmError(f"malformed llm response: {e}") from e

        usage = data.get("usage", {})
        return LlmResponse(
            content=content,
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
            prompt_hash=prompt_hash,
        )

    def chat_with_tools(
        self,
        messages: list[dict],
        *,
        tools: list[dict],
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LlmToolResponse:
        """Chat completion with OpenAI-style function-calling."""
        url = f"{self._api_base_url}/chat/completions"
        payload: dict = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

        with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
            resp = client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"},
            )

        if resp.status_code in (401, 403):
            raise LlmAuthError(f"llm auth failed: {resp.status_code}")
        if resp.status_code == 429:
            ra = resp.headers.get("Retry-After", "30")
            retry_after = int(ra) if ra.isdigit() else 30
            raise LlmRateLimitedError(retry_after_seconds=retry_after)
        if resp.status_code >= 500:
            raise LlmTransientError(f"llm 5xx: {resp.status_code}")
        if resp.status_code >= 400:
            raise LlmError(f"llm unexpected: {resp.status_code} {resp.text[:200]}")

        data = resp.json()
        try:
            message = data["choices"][0]["message"]
        except (KeyError, IndexError) as e:
            raise LlmError(f"malformed llm response: {e}") from e

        content = message.get("content") or ""
        raw_calls = message.get("tool_calls") or []
        tool_calls: list[ToolCall] = []
        for call in raw_calls:
            if not isinstance(call, dict):
                continue
            fn = call.get("function") or {}
            name = fn.get("name", "")
            raw_args = fn.get("arguments", "{}")
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
            except json.JSONDecodeError:
                args = {"__raw__": raw_args}
            tool_calls.append(
                ToolCall(id=call.get("id", ""), name=name, arguments=args if isinstance(args, dict) else {})
            )

        usage = data.get("usage", {})
        return LlmToolResponse(
            content=content,
            tool_calls=tool_calls,
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
            prompt_hash=prompt_hash,
        )
