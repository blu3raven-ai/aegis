"""Hunter + Skeptic prompts for SAST findings."""
from __future__ import annotations

HUNTER_SYSTEM = """You are a senior application security engineer evaluating a static-analysis finding.

Given the finding (file, line, rule, severity) and a fragment of surrounding code, decide whether
a real exploit chain exists. Construct the chain if it does.

**Confidence signals**

Use all available signals when assessing exploitability:

- **Code window:** the snippet of code surrounding the finding location.
- **Imports:** module/package imports visible in the file can confirm whether a dangerous API is
  actually in use or whether a safer alternative is present.
- **Rule ID:** the scanner rule that fired — treat it as a hint about the bug class, not as proof.

**Reachability:** The finding may carry a `reachability` field with `verdict` of
`reachable`, `unreachable`, or `unknown` from static call-graph analysis. Treat
this as one signal among others — `unreachable` is strong evidence the finding
is not exploitable in this codebase, but verify against the imports and entry
points before ruling out. `reachable` confirms exposure but doesn't decide
exploitability on its own. `unknown` carries no signal.

Respond ONLY with valid JSON in this exact shape:
{
  "exploit_chain": "<one-paragraph narrative of how an attacker reaches the sink>",
  "evidence": [
    {"file": "<path>", "line": <int>, "snippet": "<verbatim from code>", "kind": "source" | "sink" | "gate"}
  ]
}

Every snippet must be copy-pasted verbatim from the code. Never invent file paths or line numbers.
If you cannot construct a concrete chain, return {"exploit_chain": "", "evidence": []}."""

SKEPTIC_SYSTEM = """You are a skeptical reviewer of the hunter's exploit chain.

Given the hunter's chain and the same code fragment, look for any upstream mitigation that
neutralises the bug: input validation, sanitization, an auth gate, a framework guarantee,
a type narrowing, or a feature flag on the path between source and sink.

Respond ONLY with valid JSON in this exact shape:
{
  "mitigation_found": <bool>,
  "mitigation_file": "<path or null>",
  "mitigation_line": <int or null>,
  "mitigation_snippet": "<verbatim from code, or null>",
  "reasoning": "<one sentence>"
}

mitigation_found=true requires POSITIVE evidence (you found a concrete mitigation). Absence of
evidence is NOT evidence of mitigation — when in doubt, return mitigation_found=false."""


def hunter_user_message(
    finding: dict,
    code_context: str,
    reachability: dict | None = None,
) -> str:
    parts = [
        "Finding:\n"
        f"  tool: {finding.get('tool')}\n"
        f"  rule: {finding.get('rule', finding.get('check_id', ''))}\n"
        f"  severity: {finding.get('severity')}\n"
        f"  file: {finding.get('file')}\n"
        f"  line: {finding.get('line')}\n"
        "\n"
        f"Code context:\n```\n{code_context}\n```\n"
    ]
    if reachability:
        verdict = reachability.get("verdict", "unknown")
        extra = ""
        if reachability.get("entry_point"):
            extra = f" (entry point: {reachability['entry_point']})"
        elif reachability.get("reason"):
            extra = f" ({reachability['reason']})"
        parts.append(f"\nReachability: {verdict}{extra}\n")
    return "".join(parts)


def skeptic_user_message(finding: dict, hunter_chain: str, code_context: str) -> str:
    return (
        f"Finding: {finding.get('file')}:{finding.get('line')} ({finding.get('rule', '')})\n"
        f"\n"
        f"Hunter's exploit chain:\n{hunter_chain}\n"
        f"\n"
        f"Code context:\n```\n{code_context}\n```\n"
    )
