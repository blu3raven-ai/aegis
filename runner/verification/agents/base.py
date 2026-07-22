"""Investigator agent loop: chat -> dispatch tool calls -> repeat until final answer."""
from __future__ import annotations

import dataclasses
import json
import logging

from runner.verification.agents.conversation import ChatConversation
from runner.verification.llm_client import LlmClient
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

# Some reasoning models keep investigating with fresh (non-repeating) tool calls
# every turn and never decide, grinding to the turn cap on nearly every finding.
# Once the investigation is half-spent, nudge it once to conclude unless a
# specific gap remains — it keeps depth when genuinely needed but lets the
# already-decided case stop early instead of burning every turn.
_SOFT_CONCLUDE_DIRECTIVE = (
    "You have gathered substantial evidence. Unless a specific, named fact is "
    "still missing, stop investigating now and respond with ONLY the final JSON "
    "object required by your instructions. Do not call more tools just to be "
    "thorough."
)


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
    soft_conclude_at: int | None = None,
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
    if soft_conclude_at is None:
        soft_conclude_at = max(1, max_turns // 2)
    nudged = False
    tool_log: list[ToolCallRecord] = []
    tokens_in_total = 0
    tokens_out_total = 0
    seen_calls: set[str] = set()
    stalled_turns = 0

    tool_spec = tools.to_openai_spec()
    # Transport-agnostic conversation. A real LlmClient with the stock transport
    # delegates the responses-vs-chat choice (auto-detect + cache + fallback) to
    # start_conversation. Anything that substituted its own transport at
    # chat_with_tools (a bare stub, or a subclass that overrides it) is honored
    # by wrapping that method directly, so existing callers/tests are unchanged.
    stock_transport = getattr(type(llm), "chat_with_tools", None) is LlmClient.chat_with_tools
    if stock_transport and hasattr(llm, "start_conversation"):
        conv = llm.start_conversation(
            system_prompt=system_prompt, tools=tool_spec,
            max_tokens_per_turn=max_tokens_per_turn, temperature=0.0,
        )
    else:
        conv = ChatConversation(
            llm, system_prompt=system_prompt, tools=tool_spec,
            max_tokens_per_turn=max_tokens_per_turn, temperature=0.0,
        )

    def force_final(turns: int, pending) -> AgentResult:
        """One tool-free call so gathered work becomes a verdict, not garbage.

        Used both when turns run out and when the model is detected spinning on
        repeat tool calls. Any tool results from the triggering turn ride the
        forcing directive so they are committed before the model must answer.
        Errors degrade to the same ``llm_error`` shape the main loop uses so the
        caller's verdict logic is unchanged.
        """
        nonlocal tokens_in_total, tokens_out_total
        try:
            if pending:
                final = conv.send_tool_results(
                    pending, follow_up=_FORCE_FINAL_DIRECTIVE, disable_tools=True,
                )
            else:
                final = conv.send_user(_FORCE_FINAL_DIRECTIVE, disable_tools=True)
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

    # Drives what the next turn transmits: the opening user task, or the prior
    # turn's tool results (optionally trailed by the soft-conclude nudge).
    pending_records: list | None = None
    pending_follow_up: str | None = None
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
            if pending_records is None:
                resp = conv.send_user(user_task)
            else:
                resp = conv.send_tool_results(pending_records, follow_up=pending_follow_up)
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
            # no final JSON). Don't accept the non-answer; force a tool-free
            # answer instead of degrading the whole finding.
            logger.info("investigator completed without a usable answer; forcing at turn %d", turn)
            return force_final(turn, None)

        made_progress = False
        records: list[tuple[str, str, str]] = []
        for call in resp.tool_calls:
            record = tools.execute(call.name, call.arguments)
            tool_log.append(record)
            fp = _call_fingerprint(call.name, call.arguments)
            if fp not in seen_calls:
                seen_calls.add(fp)
                made_progress = True
            records.append((call.id, call.name, record.error or record.result))

        # A turn whose every call repeats one already run gathered nothing new.
        # Let the model recover from a single stumble, but break a hard loop
        # instead of grinding through every remaining turn.
        stalled_turns = 0 if made_progress else stalled_turns + 1
        if stalled_turns >= _STUCK_STALL_LIMIT:
            logger.warning("investigator stuck repeating tool calls; forcing answer at turn %d", turn)
            return force_final(turn, records)

        # Half-spent and still investigating: nudge it once to conclude so a
        # decided-but-indecisive model stops early instead of grinding the cap.
        pending_follow_up = None
        if turn >= soft_conclude_at and not nudged:
            pending_follow_up = _SOFT_CONCLUDE_DIRECTIVE
            nudged = True
            logger.info("investigator soft-conclude nudge at turn %d", turn)
        pending_records = records

    # Turns exhausted mid-investigation: force the answer from gathered work.
    # Logged so the exhaustion rate is visible — a high rate means the cap is
    # genuinely too low (raise it); a low rate means the cap is fine.
    logger.info("investigator hit max_turns=%d, forcing answer from gathered work", max_turns)
    return force_final(max_turns, pending_records)
