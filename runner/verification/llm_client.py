"""OpenAI-compatible chat-completions HTTP client.

Works against any OpenAI-style endpoint: OpenAI, Anthropic adapter,
Azure OpenAI, vLLM, LiteLLM, OpenRouter.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass
from typing import TypeVar

import httpx
from pydantic import BaseModel, ValidationError

logger = logging.getLogger(__name__)

# An endpoint that lacks the responses API answers a POST to /responses with a
# route-level rejection: 404/405, or (on some gateways) a 4xx whose body names
# the missing route. A 400/422 means the route exists but the request was bad,
# so those are NOT unsupported signals. Kept conservative to avoid mistaking a
# genuine bad-request for a missing endpoint.
_UNSUPPORTED_ROUTE_RE = re.compile(
    r"not\s*found|unknown|unsupported|no\s*such|does\s*not\s*exist|no\s*route|not\s*implemented",
    re.IGNORECASE,
)

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


# Total HTTP attempts per LLM call (1 initial + 3 retries). Every transient
# failure mode below shares this budget so a single call can't spin forever.
_MAX_ATTEMPTS = 4

# When a JSON response is truncated (output hit the token cap), retry the same
# prompt with this many times the cap, bounded by the ceiling. One escalation
# turns a verbose model's over-long answer into a complete, parseable one.
_TRUNCATION_ESCALATE_FACTOR = 3
_MAX_TOKENS_CEILING = 8000


def _backoff(attempt: int, cap: float = 30.0) -> None:
    """Sleep with jittered exponential backoff before a retry.

    Jittered so concurrent workers don't retry in lockstep and re-trigger the
    overload; capped so a single retry can't stall a worker indefinitely.
    """
    time.sleep(min(2 ** (attempt + 1) + random.uniform(0, 1), cap))

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


class LlmResponsesUnsupported(LlmError):
    """Raised when the configured endpoint has no responses API route.

    Internal signal that flips a client permanently onto chat completions; it is
    never a transient failure, so it does not go through the retry policy.
    """


@dataclass
class LlmResponse:
    content: str
    tokens_in: int
    tokens_out: int
    prompt_hash: str
    truncated: bool = False  # finish_reason == "length": output hit the token cap


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
    # Server-assigned id of a responses-API turn; the next turn threads it as
    # previous_response_id so only the new input is re-sent. None on the chat
    # path, which is stateless and carries the whole history every turn.
    response_id: str | None = None


def _is_unsupported_route(resp: httpx.Response) -> bool:
    """Whether a /responses reply signals the route does not exist.

    404/405 are unambiguous. A 400/422 means the route exists but the request
    was malformed, so it is never treated as unsupported. For other 4xx we fall
    back to a body-text sniff, which some gateways use for unknown paths.
    """
    if resp.status_code in (404, 405):
        return True
    if resp.status_code in (400, 401, 403, 422, 429) or resp.status_code >= 500:
        return False
    if 400 <= resp.status_code < 500:
        return bool(_UNSUPPORTED_ROUTE_RE.search(resp.text or ""))
    return False


def _to_responses_tools(tools: list[dict]) -> list[dict]:
    """Translate OpenAI chat function-tool specs to the flat responses shape.

    Chat nests the schema under ``function``; responses hoists name/description/
    parameters to the top level of each tool item.
    """
    out: list[dict] = []
    for t in tools:
        fn = t.get("function", t)
        out.append({
            "type": "function",
            "name": fn.get("name", ""),
            "description": fn.get("description", ""),
            "parameters": fn.get("parameters", {}),
        })
    return out


class LlmClient:
    def __init__(
        self, api_key: str, api_base_url: str, model: str,
        *, transport: httpx.BaseTransport | None = None, timeout: float = 60.0,
        reasoning_effort: str | None = None,
    ) -> None:
        self._api_key = api_key
        self._api_base_url = api_base_url.rstrip("/")
        self._model = model
        self._transport = transport
        self._timeout = timeout
        # Optional hint that tells a reasoning model to think less before it
        # answers. Verification is a bounded task, so deep reasoning wastes
        # tokens and starves the scan budget. Sent only when set; an endpoint
        # that rejects the field (400) makes us drop it and retry without it,
        # so it can never break a model that does not understand it. The
        # disable words let a deployment turn it off explicitly.
        effort = (reasoning_effort or "").strip().lower()
        self._reasoning_effort = None if effort in ("", "off", "none", "disabled", "0") else effort
        # Reasoning models spend completion tokens thinking before they emit the
        # JSON, so their true output need is only learned at runtime. When one
        # finding truncates and escalates, this floor ratchets up so every later
        # finding in the same scan starts with that headroom instead of each
        # paying for its own truncated first call. One client is shared across a
        # scan's concurrent findings, so the lesson is learned once. The ratchet
        # is monotonic, so a lost update under concurrency just costs one more
        # truncation, never a wrong value; no lock needed.
        self._min_completion_tokens = 0
        # Transport selection. `auto` probes the responses API once and caches
        # the result; `responses` forces it (no fallback); `chat` forces chat
        # completions and never probes. Unknown values degrade to auto.
        mode = (os.environ.get("LLM_TRANSPORT") or "auto").strip().lower()
        self._transport_mode = mode if mode in ("auto", "chat", "responses") else "auto"
        # None = not yet probed, True/False = cached capability. Shared across a
        # scan's concurrent conversations so the endpoint is probed once.
        self._supports_responses: bool | None = None

    def _post_with_retry(
        self, payload: dict, *, retry_empty: bool,
        path: str = "/chat/completions", detect_unsupported: bool = False,
    ) -> dict:
        """POST to ``path`` with the shared transient-failure retry policy,
        returning the parsed JSON body.

        Every LLM entry point (plain chat, JSON chat, tool-calling agent loop)
        funnels through here so they all get identical hardening: transport
        errors (connection / timeout / network / protocol), 429 rate limits,
        5xx, and non-JSON bodies are retried with jittered backoff; 401/403 and
        other 4xx surface immediately. ``retry_empty`` additionally retries a
        200 whose assistant content is empty — meaningful for text completions
        (the model stalled under load), but not for tool-calling turns where an
        empty content field with tool_calls is the normal shape.

        ``detect_unsupported`` (responses path only) raises
        ``LlmResponsesUnsupported`` on a route-not-found signal so the caller can
        fall back permanently; a 400/422/200 means the route exists and is not
        treated as unsupported.

        Raises the last transient error after the attempt budget is exhausted;
        the caller's ``except Exception`` degrades the finding to needs_verify.
        """
        url = f"{self._api_base_url}{path}"
        headers = {"Authorization": f"Bearer {self._api_key}", "Content-Type": "application/json"}
        last = _MAX_ATTEMPTS - 1
        last_error: Exception | None = None

        for attempt in range(_MAX_ATTEMPTS):
            try:
                with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                    resp = client.post(url, json=payload, headers=headers)
            except httpx.TransportError as e:
                # Connection refused, DNS failure, network reset, read/write
                # timeout, protocol error. All transient.
                last_error = LlmTransientError(f"llm transport: {type(e).__name__}")
                if attempt < last:
                    _backoff(attempt)
                    continue
                raise last_error

            if resp.status_code in (401, 403):
                raise LlmAuthError(f"llm auth failed: {resp.status_code}")
            if resp.status_code == 429:
                # Honor the server's Retry-After but cap it so a runaway value
                # can't stall a worker indefinitely; retry before surfacing.
                ra = resp.headers.get("Retry-After", "30")
                retry_after = int(ra) if ra.isdigit() else 30
                last_error = LlmRateLimitedError(retry_after_seconds=retry_after)
                if attempt < last:
                    time.sleep(min(retry_after, 20) + random.uniform(0, 1))
                    continue
                raise last_error
            if resp.status_code >= 500:
                last_error = LlmTransientError(f"llm 5xx: {resp.status_code}")
                if attempt < last:
                    _backoff(attempt)
                    continue
                raise last_error
            if detect_unsupported and _is_unsupported_route(resp):
                # Route does not exist: a permanent capability fact, not a
                # transient blip. Surface it so the caller flips to chat.
                raise LlmResponsesUnsupported(f"responses route unsupported: {resp.status_code}")
            if resp.status_code >= 400:
                # Fail open on a rejected reasoning hint: some OpenAI-compatible
                # endpoints 400 on the unknown field (top-level reasoning_effort
                # on the chat path, or the nested reasoning object on responses).
                # Drop it, disable it for the rest of this client's life, retry.
                if resp.status_code == 400 and (
                    payload.pop("reasoning_effort", None) is not None
                    or payload.pop("reasoning", None) is not None
                ):
                    self._reasoning_effort = None
                    logger.info("llm endpoint rejected reasoning_effort; retrying without it")
                    last_error = LlmTransientError("reasoning_effort rejected")
                    if attempt < last:
                        continue
                    raise last_error
                raise LlmError(f"llm unexpected: {resp.status_code} {resp.text[:200]}")

            try:
                # A non-JSON body (e.g. an HTML error page from a proxy under
                # load) raises ValueError. Transient; retry.
                data = resp.json()
            except ValueError as e:
                last_error = LlmTransientError(f"llm non-json response: {type(e).__name__}")
                if attempt < last:
                    _backoff(attempt)
                    continue
                raise last_error

            if retry_empty and attempt < last:
                # A 200 with empty assistant content is a transient overload
                # for a text completion; back off and retry before accepting it.
                try:
                    content = data["choices"][0]["message"].get("content") or ""
                except (KeyError, IndexError):
                    content = ""
                if not _strip_fences(content):
                    last_error = LlmTransientError("llm returned empty content")
                    _backoff(attempt)
                    continue

            return data

        # Unreachable: every branch either returns or raises on the last attempt.
        raise last_error if last_error is not None else LlmError("llm failed after retries")

    def chat(self, messages: list[dict], *, temperature: float = 0.0, max_tokens: int = 1024) -> LlmResponse:
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if self._reasoning_effort:
            payload["reasoning_effort"] = self._reasoning_effort
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        data = self._post_with_retry(payload, retry_empty=True)
        try:
            choice = data["choices"][0]
            # content can be null when the model refuses or hits a length cap;
            # coerce to "" so _strip_fences and the caller's repair path handle
            # it instead of crashing on None.strip().
            content = choice["message"].get("content") or ""
        except (KeyError, IndexError) as e:
            raise LlmError(f"malformed llm response: {e}") from e
        usage = data.get("usage", {})
        return LlmResponse(
            content=_strip_fences(content),
            tokens_in=int(usage.get("prompt_tokens", 0)),
            tokens_out=int(usage.get("completion_tokens", 0)),
            prompt_hash=prompt_hash,
            truncated=choice.get("finish_reason") == "length",
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

        A truncated response (output hit the token cap) is not a format error a
        repair prompt can fix, so it is instead retried on the ORIGINAL prompt
        with a larger cap. Verbose or reasoning-style models overrun a tight cap
        on hard findings; the escalation lets the response complete, and the
        learned headroom carries to later findings in the same scan.
        """
        convo = list(messages)
        # Start at the floor a prior finding's reasoning spike already taught us.
        cur_max_tokens = max(max_tokens, self._min_completion_tokens)
        tokens_in = 0
        tokens_out = 0
        prompt_hashes: list[str] = []
        last_error = ""

        for attempt in range(max_repairs + 1):
            resp = self.chat(convo, temperature=temperature, max_tokens=cur_max_tokens)
            tokens_in += resp.tokens_in
            tokens_out += resp.tokens_out
            prompt_hashes.append(resp.prompt_hash)
            try:
                parsed = model_cls.model_validate_json(_strip_fences(resp.content))
            except (ValidationError, ValueError) as exc:
                last_error = str(exc)
                if attempt >= max_repairs:
                    break
                if resp.truncated:
                    cur_max_tokens = min(cur_max_tokens * _TRUNCATION_ESCALATE_FACTOR, _MAX_TOKENS_CEILING)
                    convo = list(messages)
                    # Remember the model needs this much room so later findings
                    # in the scan start here instead of truncating first.
                    self._min_completion_tokens = max(self._min_completion_tokens, cur_max_tokens)
                else:
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
        """Chat completion with OpenAI-style function-calling.

        Shares the same transient-failure retry policy as ``chat`` via
        ``_post_with_retry`` so the investigator loop survives a 429 / 5xx /
        connection blip instead of aborting the whole run. ``retry_empty`` is
        False here: an empty content field alongside tool_calls is the normal
        shape for a tool-calling turn, not a stall.
        """
        payload: dict = {
            "model": self._model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = tools
        if self._reasoning_effort:
            payload["reasoning_effort"] = self._reasoning_effort
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

        data = self._post_with_retry(payload, retry_empty=False)
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

    def _responses_turn(
        self,
        input_items: list[dict],
        *,
        tools: list[dict],
        previous_response_id: str | None,
        temperature: float,
        max_tokens: int,
    ) -> LlmToolResponse:
        """Run one turn against the responses API.

        Sends only ``input_items`` (the new user/tool input) plus
        ``previous_response_id``; the server retains prior context, which is the
        multi-turn token win over re-sending the whole history each turn. On the
        first probe in ``auto`` mode an unsupported endpoint flips the client
        permanently onto chat completions (logged once); a real bad request or a
        transient blip is not treated as unsupported.
        """
        payload: dict = {
            "model": self._model,
            "input": input_items,
            "temperature": temperature,
            "max_output_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = _to_responses_tools(tools)
        if previous_response_id:
            payload["previous_response_id"] = previous_response_id
        if self._reasoning_effort:
            payload["reasoning"] = {"effort": self._reasoning_effort}
        prompt_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()

        try:
            data = self._post_with_retry(
                payload, retry_empty=False, path="/responses", detect_unsupported=True,
            )
        except LlmResponsesUnsupported:
            if self._supports_responses is None:
                logger.info("endpoint does not support the responses api; using chat completions")
            self._supports_responses = False
            raise
        # A parseable turn confirms the route exists; cache so peers skip probing.
        self._supports_responses = True

        content_parts: list[str] = []
        tool_calls: list[ToolCall] = []
        for item in data.get("output") or []:
            if not isinstance(item, dict):
                continue
            itype = item.get("type")
            if itype == "message":
                for part in item.get("content") or []:
                    if isinstance(part, dict) and part.get("type") in ("output_text", "text"):
                        content_parts.append(part.get("text", ""))
            elif itype == "function_call":
                raw_args = item.get("arguments", "{}")
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                except json.JSONDecodeError:
                    args = {"__raw__": raw_args}
                tool_calls.append(ToolCall(
                    # call_id threads the tool result back on the next turn.
                    id=item.get("call_id") or item.get("id", ""),
                    name=item.get("name", ""),
                    arguments=args if isinstance(args, dict) else {},
                ))

        usage = data.get("usage", {})
        return LlmToolResponse(
            content="".join(content_parts),
            tool_calls=tool_calls,
            tokens_in=int(usage.get("input_tokens", 0)),
            tokens_out=int(usage.get("output_tokens", 0)),
            prompt_hash=prompt_hash,
            response_id=data.get("id"),
        )

    def start_conversation(
        self, *, system_prompt: str, tools: list[dict],
        max_tokens_per_turn: int, temperature: float = 0.0,
    ):
        """Open a transport-agnostic multi-turn conversation.

        Picks the responses API when the endpoint supports it (cached per
        client) and falls back to stateless chat completions otherwise, honoring
        the ``LLM_TRANSPORT`` override. The agent loop drives the returned
        object without knowing which transport backs it.
        """
        from runner.verification.agents.conversation import ChatConversation, ResponsesConversation

        kwargs = dict(
            system_prompt=system_prompt, tools=tools,
            max_tokens_per_turn=max_tokens_per_turn, temperature=temperature,
        )
        if self._transport_mode == "chat" or self._supports_responses is False:
            return ChatConversation(self, **kwargs)
        # `responses` forces it with no fallback; `auto` allows degrade-to-chat.
        return ResponsesConversation(
            self, allow_fallback=self._transport_mode == "auto", **kwargs,
        )
