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

import json

from runner.verification.llm_client import LlmResponsesUnsupported, LlmToolResponse


def _assistant_message(resp: LlmToolResponse) -> dict:
    """Chat-shaped assistant message mirroring a turn, so providers can
    correlate the tool responses that follow it."""
    msg: dict = {"role": "assistant", "content": resp.content or None}
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
