"""Turn a runtime_question into a BENIGN, read-only probe spec.

A probe only OBSERVES the running target to answer the verification question — it
never exploits, mutates, exfiltrates, or runs destructive actions. Same benign-lock
philosophy as PoC generation: the safety rules live in the system prompt, and the
spec is a structured, auditable description of the HTTP checks to run inside the
sandbox (never free-form code).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ProbeRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    method: str = "GET"          # observation verbs only; enforced downstream
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    # True = send a valid credential (the "control present?" A/B baseline);
    # False = send none (the "is it exposed without auth?" case).
    authenticated: bool = False


class ProbeSpec(BaseModel):
    """A read-only plan for answering one runtime-verification question."""

    model_config = ConfigDict(extra="ignore")

    port: int = 0
    requests: list[ProbeRequest] = Field(default_factory=list)
    # How to read the responses:
    flaw_signal: str = ""      # e.g. "any 2xx to /admin with no credential"
    control_signal: str = ""   # e.g. "401 or 403 without a credential"


_PROBE_SYSTEM = """You are generating a BENIGN, READ-ONLY probe to answer ONE runtime \
security question about a web service that is already running on loopback in a \
sandbox. The probe only OBSERVES behavior to confirm or refute the question.

HARD RULES — the probe MUST NOT:
  - exploit the flaw, mutate/delete data, or perform any destructive or \
    state-changing action beyond the minimal request needed to observe the answer;
  - exfiltrate data, call external hosts, or run shell/code — it is HTTP requests only;
  - use another user's real credential or brute-force anything.

Prefer GET/HEAD. Use at most a couple of requests: typically one with NO credential \
(to see if the endpoint is exposed) and, when useful, one WITH a benign/placeholder \
credential as the baseline. Describe in flaw_signal what response proves the flaw is \
real, and in control_signal what response proves the control is present.

Respond ONLY with valid JSON in this exact shape:
{
  "port": <int, the port the app listens on; 0 if unknown>,
  "requests": [
    {"method": "GET", "path": "/<path>", "headers": {}, "authenticated": false}
  ],
  "flaw_signal": "<what response confirms the flaw>",
  "control_signal": "<what response shows the control is present>"
}"""


def _probe_user(runtime_question: str, port_hint: int | None) -> str:
    hint = f"\nThe app likely listens on port {port_hint}." if port_hint else ""
    return f"Runtime question to answer:\n{runtime_question}{hint}"


def generate_probe(
    runtime_question: str, *, llm, port_hint: int | None = None,
) -> ProbeSpec | None:
    """Generate a benign probe spec for the question, or None (no LLM / no question
    / schema failure) — the caller then skips runtime verification for this finding."""
    if llm is None or not (runtime_question or "").strip():
        return None
    result = llm.chat_json(
        [
            {"role": "system", "content": _PROBE_SYSTEM},
            {"role": "user", "content": _probe_user(runtime_question, port_hint)},
        ],
        ProbeSpec,
        temperature=0.0, max_tokens=500,
    )
    spec = result.parsed
    if spec is None or not spec.requests:
        return None
    return spec
