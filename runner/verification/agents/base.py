"""Investigator agent loop: chat -> dispatch tool calls -> repeat until final answer."""
from __future__ import annotations

import dataclasses
import json
import logging
from typing import Any

from runner.verification.tools.base import ToolCallRecord, ToolRegistry

logger = logging.getLogger(__name__)


# A hunter tracing source -> gate -> sink across files needs several distinct
# grep/read rounds before it can synthesise a verdict. 8 was tight enough that a
# thorough investigation ran out mid-trace; the forcing turn + stuck-loop harness
# make a higher cap safe (spinning is cut off early, the token budget bounds cost).
_DEFAULT_MAX_TURNS = 12
_DEFAULT_MAX_TOKENS_PER_TURN = 1000

# When the loop exhausts its turns still mid-investigation, spend one final call
# with tools disabled so the model is forced to commit its answer from what it
# has already gathered. Without this, a model that keeps grepping/reading until
# the last turn yields no final JSON and the whole investigation is discarded.
_FORCE_FINAL_DIRECTIVE = (
    "You have used all available investigation steps. Do not call any more tools. "
    "Respond NOW with ONLY the final JSON object required by your instructions, "
    "based on everything you have gathered."
)

# A model that re-issues tool calls it has already made is spinning, not
# investigating. After this many consecutive no-progress turns (every call a
# repeat of one already run) we stop feeding it turns and force the answer.
_STUCK_STALL_LIMIT = 2


@dataclasses.dataclass
class AgentResult:
    """Final output of an investigator run."""

    final_message: str
    tool_calls: list[ToolCallRecord]
    tokens_in: int
    tokens_out: int
    turns: int
    stopped_reason: str  # 'completed' | 'forced_final' | 'budget' | 'llm_error'


def _call_fingerprint(name: str, arguments: dict) -> str:
    return f"{name}:{json.dumps(arguments, sort_keys=True, default=str)}"


def investigate(
    *,
    system_prompt: str,
    user_task: str,
    tools: ToolRegistry,
    llm,
    max_turns: int = _DEFAULT_MAX_TURNS,
    max_tokens_per_turn: int = _DEFAULT_MAX_TOKENS_PER_TURN,
    budget=None,
    is_final=None,
) -> AgentResult:
    """Run the agent loop. ``llm`` must implement ``chat_with_tools``.

    ``is_final`` decides whether a tool-free model turn is actually the answer.
    A reasoning model sometimes stops calling tools and returns prose (its
    thinking) with no final JSON; accepting that as "completed" hands the caller
    a non-answer. The verification caller passes a predicate that checks the
    content really contains the schema JSON, so a prose-only turn triggers the
    forcing turn instead of being taken at face value. Defaults to "any
    non-empty content is final" for schema-agnostic callers.
    """
    if is_final is None:
        is_final = lambda content: bool((content or "").strip())  # noqa: E731
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_task},
    ]
    tool_log: list[ToolCallRecord] = []
    tokens_in_total = 0
    tokens_out_total = 0
    seen_calls: set[str] = set()
    stalled_turns = 0

    tool_spec = tools.to_openai_spec()

    def force_final(turns: int) -> AgentResult:
        """One tool-free call so gathered work becomes a verdict, not garbage.

        Used both when turns run out and when the model is detected spinning on
        repeat tool calls. Errors degrade to the same ``llm_error`` shape the
        main loop uses so the caller's verdict logic is unchanged.
        """
        nonlocal tokens_in_total, tokens_out_total
        messages.append({"role": "user", "content": _FORCE_FINAL_DIRECTIVE})
        try:
            final = llm.chat_with_tools(
                messages, tools=[], temperature=0.0, max_tokens=max_tokens_per_turn,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("investigator forced-final llm error: %s", exc)
            return AgentResult(
                final_message=f"// stopped: llm error ({type(exc).__name__})",
                tool_calls=tool_log,
                tokens_in=tokens_in_total,
                tokens_out=tokens_out_total,
                turns=turns,
                stopped_reason="llm_error",
            )
        tokens_in_total += final.tokens_in
        tokens_out_total += final.tokens_out
        if budget is not None:
            budget.record(tokens_in=final.tokens_in, tokens_out=final.tokens_out)
        return AgentResult(
            final_message=final.content or "",
            tool_calls=tool_log,
            tokens_in=tokens_in_total,
            tokens_out=tokens_out_total,
            turns=turns,
            stopped_reason="forced_final",
        )

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
            if is_final(resp.content or ""):
                return AgentResult(
                    final_message=resp.content or "",
                    tool_calls=tool_log,
                    tokens_in=tokens_in_total,
                    tokens_out=tokens_out_total,
                    turns=turn,
                    stopped_reason="completed",
                )
            # Stopped calling tools but gave no usable answer (reasoning prose,
            # no final JSON). Don't accept the non-answer — record it and force a
            # tool-free answer instead of degrading the whole finding.
            logger.info("investigator completed without a usable answer; forcing at turn %d", turn)
            messages.append({"role": "assistant", "content": resp.content or ""})
            return force_final(turn)

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
        made_progress = False
        for call in resp.tool_calls:
            record = tools.execute(call.name, call.arguments)
            tool_log.append(record)
            fp = _call_fingerprint(call.name, call.arguments)
            if fp not in seen_calls:
                seen_calls.add(fp)
                made_progress = True
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": record.error or record.result,
                }
            )

        # A turn whose every call repeats one already run gathered nothing new.
        # Let the model recover from a single stumble, but break a hard loop
        # instead of grinding through every remaining turn.
        stalled_turns = 0 if made_progress else stalled_turns + 1
        if stalled_turns >= _STUCK_STALL_LIMIT:
            logger.warning("investigator stuck repeating tool calls; forcing answer at turn %d", turn)
            return force_final(turn)

    # Turns exhausted mid-investigation: force the answer from gathered work.
    # Logged so the exhaustion rate is visible — a high rate means the cap is
    # genuinely too low (raise it); a low rate means the cap is fine.
    logger.info("investigator hit max_turns=%d, forcing answer from gathered work", max_turns)
    return force_final(max_turns)
