"""Investigator agent loop: chat -> dispatch tool calls -> repeat until final answer."""
from __future__ import annotations

import dataclasses
import json
import logging
from typing import Any

from argus.verification.tools.base import ToolCallRecord, ToolRegistry

logger = logging.getLogger(__name__)


_DEFAULT_MAX_TURNS = 8
_DEFAULT_MAX_TOKENS_PER_TURN = 1000


@dataclasses.dataclass
class AgentResult:
    """Final output of an investigator run."""

    final_message: str
    tool_calls: list[ToolCallRecord]
    tokens_in: int
    tokens_out: int
    turns: int
    stopped_reason: str  # 'completed' | 'max_turns' | 'budget' | 'llm_error'


def investigate(
    *,
    system_prompt: str,
    user_task: str,
    tools: ToolRegistry,
    llm,
    max_turns: int = _DEFAULT_MAX_TURNS,
    max_tokens_per_turn: int = _DEFAULT_MAX_TOKENS_PER_TURN,
    budget=None,
) -> AgentResult:
    """Run the agent loop. ``llm`` must implement ``chat_with_tools``."""
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_task},
    ]
    tool_log: list[ToolCallRecord] = []
    tokens_in_total = 0
    tokens_out_total = 0

    tool_spec = tools.to_openai_spec()

    for turn in range(1, max_turns + 1):
        if budget is not None and not budget.allow():
            return AgentResult(
                final_message="// stopped: token budget exhausted",
                tool_calls=tool_log,
                tokens_in=tokens_in_total,
                tokens_out=tokens_out_total,
                turns=turn - 1,
                stopped_reason="budget",
            )

        try:
            resp = llm.chat_with_tools(
                messages,
                tools=tool_spec,
                temperature=0.0,
                max_tokens=max_tokens_per_turn,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("investigator llm error on turn %d: %s", turn, exc)
            return AgentResult(
                final_message=f"// stopped: llm error ({type(exc).__name__})",
                tool_calls=tool_log,
                tokens_in=tokens_in_total,
                tokens_out=tokens_out_total,
                turns=turn - 1,
                stopped_reason="llm_error",
            )

        tokens_in_total += resp.tokens_in
        tokens_out_total += resp.tokens_out
        if budget is not None:
            budget.record(tokens_in=resp.tokens_in, tokens_out=resp.tokens_out)

        if not resp.tool_calls:
            return AgentResult(
                final_message=resp.content or "",
                tool_calls=tool_log,
                tokens_in=tokens_in_total,
                tokens_out=tokens_out_total,
                turns=turn,
                stopped_reason="completed",
            )

        # Persist assistant message verbatim so providers can correlate tool responses.
        messages.append(
            {
                "role": "assistant",
                "content": resp.content or None,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {
                            "name": call.name,
                            "arguments": json.dumps(call.arguments),
                        },
                    }
                    for call in resp.tool_calls
                ],
            }
        )
        for call in resp.tool_calls:
            record = tools.execute(call.name, call.arguments)
            tool_log.append(record)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": record.error or record.result,
                }
            )

    return AgentResult(
        final_message="// stopped: hit max_turns without final answer",
        tool_calls=tool_log,
        tokens_in=tokens_in_total,
        tokens_out=tokens_out_total,
        turns=max_turns,
        stopped_reason="max_turns",
    )
