"""Capability-aware conversation transport for the investigator loop.

Two implementations share one interface so the agent loop is transport-agnostic:

- ``ChatConversation`` accumulates the full message array and re-sends it every
  turn against ``/chat/completions`` (stateless; the compatibility baseline).
- ``ResponsesConversation`` keeps ``previous_response_id`` and sends only the new
  input each turn against ``/responses`` (stateful; the multi-turn token win).

Both accept the same ``send_user`` / ``send_tool_results`` calls and return an
``LlmToolResponse``, so ``investigate`` never branches on the transport.
"""
from __future__ import annotations

import copy
import json

from runner.verification.llm_client import LlmResponsesUnsupported, LlmToolResponse


def _assistant_message(resp: LlmToolResponse) -> dict:
    """Chat-shaped assistant message mirroring a turn, so providers can
    correlate the tool responses that follow it."""
    # Some endpoints reject a null/absent content field on an assistant message
    # (they require the key even when the turn is only tool calls); send "" so a
    # tool-call turn does not 400.
    msg: dict = {"role": "assistant", "content": resp.content or ""}
    if resp.tool_calls:
        msg["tool_calls"] = [
            {
                "id": call.id,
                "type": "function",
                "function": {"name": call.name, "arguments": json.dumps(call.arguments)},
            }
            for call in resp.tool_calls
        ]
    return msg


class ChatConversation:
    """Stateless chat-completions transport: the whole history every turn."""

    def __init__(
        self, llm, *, system_prompt: str, tools: list[dict],
        max_tokens_per_turn: int, temperature: float,
    ) -> None:
        self._llm = llm
        self._tools = tools
        self._max_tokens = max_tokens_per_turn
        self._temperature = temperature
        self._messages: list[dict] = [{"role": "system", "content": system_prompt}]

    def send_user(self, text: str, *, disable_tools: bool = False) -> LlmToolResponse:
        self._messages.append({"role": "user", "content": text})
        return self._turn(disable_tools=disable_tools)

    def send_tool_results(
        self, results, *, follow_up: str | None = None, disable_tools: bool = False,
    ) -> LlmToolResponse:
        for tool_call_id, name, content in results:
            self._messages.append(
                {"role": "tool", "tool_call_id": tool_call_id, "name": name, "content": content}
            )
        if follow_up:
            self._messages.append({"role": "user", "content": follow_up})
        return self._turn(disable_tools=disable_tools)

    def _turn(self, *, disable_tools: bool) -> LlmToolResponse:
        resp = self._llm.chat_with_tools(
            self._messages,
            tools=[] if disable_tools else self._tools,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        self._messages.append(_assistant_message(resp))
        return resp


def _anthropic_assistant_message(resp: LlmToolResponse) -> dict:
    """Reconstruct the assistant turn as Anthropic content blocks.

    Preserves each tool_use id so the following user turn's tool_result can
    correlate to it. Text rides as a text block; thinking blocks are dropped (the
    turn method already discarded them). Kept in history for multi-turn context.
    """
    content: list[dict] = []
    if resp.content:
        content.append({"type": "text", "text": resp.content})
    for call in resp.tool_calls:
        content.append({
            "type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments,
        })
    if not content:
        # An assistant message needs at least one block; only reachable on an
        # empty terminal turn, which is never re-sent.
        content.append({"type": "text", "text": ""})
    return {"role": "assistant", "content": content}


class AnthropicConversation:
    """Anthropic Messages transport with native prompt caching.

    Accumulates the conversation as Anthropic content-block messages and re-sends
    it each turn. Two cache breakpoints are placed per request: a static one on
    the system prompt and a moving one on the last content block of the last
    message, so the whole growing prefix is cached and the next turn reads it back
    cheaply. Breakpoints are stamped on a per-turn deep copy so the stored history
    stays clean and the count never exceeds two.
    """

    def __init__(
        self, client, *, system_prompt: str, tools: list[dict],
        max_tokens_per_turn: int, temperature: float,
    ) -> None:
        self._client = client
        self._system_prompt = system_prompt
        self._tools = tools
        self._max_tokens = max_tokens_per_turn
        # temperature is accepted for interface parity; the verified Anthropic
        # body for this task omits it and uses the endpoint default.
        self._messages: list[dict] = []

    def send_user(self, text: str, *, disable_tools: bool = False) -> LlmToolResponse:
        self._messages.append({"role": "user", "content": [{"type": "text", "text": text}]})
        return self._turn(disable_tools=disable_tools)

    def send_tool_results(
        self, results, *, follow_up: str | None = None, disable_tools: bool = False,
    ) -> LlmToolResponse:
        content: list[dict] = [
            {"type": "tool_result", "tool_use_id": tool_call_id, "content": result}
            for tool_call_id, _name, result in results
        ]
        if follow_up:
            content.append({"type": "text", "text": follow_up})
        self._messages.append({"role": "user", "content": content})
        return self._turn(disable_tools=disable_tools)

    def _turn(self, *, disable_tools: bool) -> LlmToolResponse:
        system, messages = self._cached_request()
        resp = self._client._anthropic_turn(
            system, messages,
            tools=[] if disable_tools else self._tools,
            max_tokens=self._max_tokens,
            disable_tools=disable_tools,
        )
        self._messages.append(_anthropic_assistant_message(resp))
        return resp

    def _cached_request(self) -> tuple[list[dict], list[dict]]:
        """Build the (system, messages) request copy with the two breakpoints.

        Deep-copies messages so the moving breakpoint never accumulates in the
        stored history; stamps cache_control on the system block and on the last
        content block of the last message. Exactly two breakpoints, well under
        Anthropic's max of four.
        """
        system = [{
            "type": "text", "text": self._system_prompt,
            "cache_control": {"type": "ephemeral"},
        }]
        messages = copy.deepcopy(self._messages)
        if messages and messages[-1].get("content"):
            messages[-1]["content"][-1]["cache_control"] = {"type": "ephemeral"}
        return system, messages


class ResponsesConversation:
    """Stateful responses transport: only the new input delta each turn.

    Threads ``previous_response_id`` so prior context stays server-side. A shadow
    chat-shaped message list is kept solely so a mid-conversation unsupported
    signal (shouldn't happen after the first turn) can degrade to chat by
    replaying the accumulated logical history.
    """

    def __init__(
        self, client, *, system_prompt: str, tools: list[dict],
        max_tokens_per_turn: int, temperature: float, allow_fallback: bool,
    ) -> None:
        self._client = client
        self._system_prompt = system_prompt
        self._tools = tools
        self._max_tokens = max_tokens_per_turn
        self._temperature = temperature
        self._allow_fallback = allow_fallback
        self._prev_id: str | None = None
        self._system_pending = True
        self._shadow: list[dict] = [{"role": "system", "content": system_prompt}]
        self._fallback: ChatConversation | None = None

    def send_user(self, text: str, *, disable_tools: bool = False) -> LlmToolResponse:
        if self._fallback is not None:
            return self._fallback.send_user(text, disable_tools=disable_tools)
        items: list[dict] = []
        # The system prompt rides the first input as a message; the stateful
        # server retains it, so later turns re-send only their delta.
        if self._system_pending:
            items.append({"role": "system", "content": self._system_prompt})
            self._system_pending = False
        items.append({"role": "user", "content": text})
        self._shadow.append({"role": "user", "content": text})
        return self._turn(items, disable_tools=disable_tools)

    def send_tool_results(
        self, results, *, follow_up: str | None = None, disable_tools: bool = False,
    ) -> LlmToolResponse:
        if self._fallback is not None:
            return self._fallback.send_tool_results(
                results, follow_up=follow_up, disable_tools=disable_tools
            )
        items: list[dict] = []
        for tool_call_id, name, content in results:
            items.append(
                {"type": "function_call_output", "call_id": tool_call_id, "output": content}
            )
            self._shadow.append(
                {"role": "tool", "tool_call_id": tool_call_id, "name": name, "content": content}
            )
        if follow_up:
            items.append({"role": "user", "content": follow_up})
            self._shadow.append({"role": "user", "content": follow_up})
        return self._turn(items, disable_tools=disable_tools)

    def _turn(self, input_items: list[dict], *, disable_tools: bool) -> LlmToolResponse:
        try:
            resp = self._client._responses_turn(
                input_items,
                tools=[] if disable_tools else self._tools,
                previous_response_id=self._prev_id,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )
        except LlmResponsesUnsupported:
            if not self._allow_fallback:
                raise
            return self._degrade_and_retry(disable_tools=disable_tools)
        self._prev_id = resp.response_id or self._prev_id
        self._shadow.append(_assistant_message(resp))
        return resp

    def _degrade_and_retry(self, *, disable_tools: bool) -> LlmToolResponse:
        # Replay the accumulated logical history over chat completions. The
        # current turn's input is already in the shadow, so re-run it directly.
        fb = ChatConversation(
            self._client,
            system_prompt=self._system_prompt,
            tools=self._tools,
            max_tokens_per_turn=self._max_tokens,
            temperature=self._temperature,
        )
        fb._messages = list(self._shadow)
        self._fallback = fb
        return fb._turn(disable_tools=disable_tools)
