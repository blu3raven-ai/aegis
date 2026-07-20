"""OpenAI-compatible chat-completions HTTP client.

Works against any OpenAI-style endpoint: OpenAI, Anthropic adapter,
Azure OpenAI, vLLM, LiteLLM, OpenRouter.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

# Many self-hostable models wrap JSON in ```json ... ``` fences despite the
# system prompt saying "raw JSON only". Stripping before validation avoids a
# spurious repair round-trip that doubles token cost and can degrade the
# verdict when the retry comes back emptier than the first attempt.
_FENCE_OPEN = re.compile(r"^\s*```[a-zA-Z0-9_+-]*\s*\n?")
_FENCE_CLOSE = re.compile(r"\n?\s*```\s*$")


def _strip_fences(content: str) -> str:
    s = content.strip()
    if not s.startswith("```"):
        return s
    s = _FENCE_OPEN.sub("", s, count=1)
    s = _FENCE_CLOSE.sub("", s, count=1)
    return s.strip()

_T = TypeVar("_T", bound=BaseModel)

# Re-prompt used when a structured response fails schema validation. Weaker
# self-hostable models frequently emit prose or malformed JSON on the first
# turn but recover when handed the validation error and asked for raw JSON.
_REPAIR_INSTRUCTION = (
    "Your previous response failed schema validation with this error:\n"
    "{error}\n\n"
    "Reply with ONLY a single valid JSON object matching the {schema_name} "
    "schema below. Do not include any prose, explanation, or markdown code "
    "fences — output the raw JSON object and nothing else.\n\n"
    "Schema:\n{schema}"
)


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
class JsonChatResult:
    """Outcome of a schema-validated chat, including any repair attempt.

    ``parsed`` is the validated model on success or ``None`` when validation
    failed after all attempts (the caller then falls back). Token counts and
    ``prompt_hashes`` accumulate across every attempt, including repairs.
    """

    parsed: BaseModel | None
    error: str | None
    tokens_in: int
    tokens_out: int
    prompt_hashes: list[str]


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
            # content can be null when the model refuses or hits a length cap;
            # coerce to "" so _strip_fences and the repair path handle it
            # instead of crashing on None.strip().
            content = data["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError) as e:
            raise LlmError(f"malformed llm response: {e}") from e

        usage = data.get("usage", {})
        return LlmResponse(
            content=_strip_fences(content),
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
            prompt_hash=prompt_hash,
        )

    def chat_json(
        self,
        messages: list[dict],
        model_cls: type[_T],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        max_repairs: int = 1,
    ) -> JsonChatResult:
        """Chat, validate against ``model_cls``, and repair-retry once on failure.

        On a schema-invalid response the model is re-prompted (up to
        ``max_repairs`` times) with the validation error and a request for raw
        JSON. This only recovers the verdict the model already intended — it
        never changes verdict logic. A valid first response costs exactly one
        call; exhausting the repairs returns ``parsed=None`` so the caller can
        apply its existing fallback. Transport-level errors
        (``LlmRateLimitedError`` / ``LlmError``) propagate unchanged.
        """
        convo = list(messages)
        tokens_in = 0
        tokens_out = 0
        prompt_hashes: list[str] = []
        last_error = ""

        for attempt in range(max_repairs + 1):
            resp = self.chat(convo, temperature=temperature, max_tokens=max_tokens)
            tokens_in += resp.tokens_in
            tokens_out += resp.tokens_out
            prompt_hashes.append(resp.prompt_hash)
            try:
                parsed = model_cls.model_validate_json(_strip_fences(resp.content))
            except (ValidationError, ValueError) as exc:
                last_error = str(exc)
                if attempt >= max_repairs:
                    break
                convo = convo + [
                    {"role": "assistant", "content": resp.content},
                    {"role": "user", "content": _REPAIR_INSTRUCTION.format(
                        error=last_error,
                        schema_name=model_cls.__name__,
                        schema=json.dumps(model_cls.model_json_schema()),
                    )},
                ]
                continue
            return JsonChatResult(
                parsed=parsed, error=None,
                tokens_in=tokens_in, tokens_out=tokens_out,
                prompt_hashes=prompt_hashes,
            )

        return JsonChatResult(
            parsed=None, error=last_error,
            tokens_in=tokens_in, tokens_out=tokens_out,
            prompt_hashes=prompt_hashes,
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
