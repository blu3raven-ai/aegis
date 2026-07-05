"""Deterministic replay stand-in for the verification LLM client.

Substitutes a live model with a queue of pre-recorded responses so the
verifiers run identically offline — no key, no network, no flakiness. The
queue is popped in recorded order, so a single-shot verifier (deps) and a
multi-call one (hunter -> skeptic) both replay correctly.
"""
from __future__ import annotations

from collections import deque
from typing import Any

from pydantic import ValidationError

from runner.verification.llm_client import JsonChatResult, LlmResponse


class ReplayError(RuntimeError):
    """A fixture supplied fewer responses than the verifier consumed."""


class ReplayLlm:
    """Returns queued ``LlmResponse`` objects in the order they were recorded.

    Implements both ``chat`` (single-shot deps verifier) and ``chat_json``
    (hunter/skeptic verifiers) against the same queue, mirroring
    ``LlmClient``'s contract closely enough that the verifiers cannot tell the
    difference. ``chat_json`` replays one queued response per call and applies
    the same schema-validate-then-repair-once loop as the real client, so a
    fixture testing the repair path just supplies a bad-then-good pair.
    """

    def __init__(self, responses: list[Any], *, model: str = "replay") -> None:
        self._queue: deque[LlmResponse] = deque(_to_response(r) for r in responses)
        # Verifiers read ``_model`` for metadata; mirror the real client attr.
        self._model = model
        self.calls = 0

    def chat(
        self,
        messages: list[dict],
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ) -> LlmResponse:
        # Fail loudly on under-supply rather than silently returning a stale or
        # empty response — a missing recording is a fixture bug, not a pass.
        if not self._queue:
            raise ReplayError(
                f"replay under-supplied: verifier requested response #{self.calls + 1} "
                "but the fixture ran out of recorded responses"
            )
        self.calls += 1
        return self._queue.popleft()

    def chat_json(
        self,
        messages: list[dict],
        model_cls: type,
        *,
        temperature: float = 0.0,
        max_tokens: int = 1024,
        max_repairs: int = 1,
    ) -> JsonChatResult:
        """Replay-backed mirror of ``LlmClient.chat_json``.

        Pops one queued response per attempt, validates it against
        ``model_cls``, and — on a schema failure with repair budget remaining —
        re-prompts and pops the next response. A valid first response costs
        exactly one queue entry, matching the real client. Exhausting the
        budget returns ``parsed=None`` so the verifier applies its existing
        fallback.
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
                parsed = model_cls.model_validate_json(resp.content)
            except (ValidationError, ValueError) as exc:
                last_error = str(exc)
                if attempt >= max_repairs:
                    break
                convo = convo + [
                    {"role": "assistant", "content": resp.content},
                    {"role": "user", "content": _REPAIR_INSTRUCTION.format(
                        error=last_error,
                        schema_name=model_cls.__name__,
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


# Mirrors the spirit of ``LlmClient``'s repair instruction without dragging the
# live client's full JSON-schema dump into the replay path (the recorded
# response already encodes what the model would have said).
_REPAIR_INSTRUCTION = (
    "Your previous response for {schema_name} failed schema validation: "
    "{error}\nRe-emit the answer as raw JSON only."
)


def _to_response(raw: Any) -> LlmResponse:
    """Coerce a recorded dict (or an already-built response) into ``LlmResponse``."""
    if isinstance(raw, LlmResponse):
        return raw
    if not isinstance(raw, dict):
        raise ReplayError(f"recorded response must be a dict, got {type(raw).__name__}")
    content = raw.get("content")
    if not isinstance(content, str):
        raise ReplayError("recorded response is missing a string 'content' field")
    return LlmResponse(
        content=content,
        tokens_in=int(raw.get("tokens_in", 0)),
        tokens_out=int(raw.get("tokens_out", 0)),
        prompt_hash=str(raw.get("prompt_hash", "replay")),
    )
