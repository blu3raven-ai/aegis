"""Hunter + Skeptic prompts for secret-scan findings."""
from __future__ import annotations

HUNTER_SYSTEM_SECRET = """You are a senior security engineer evaluating a TruffleHog candidate secret.

Given a string TruffleHog matched against a credential pattern, decide whether it is:
- A REAL leaked credential an attacker could use, OR
- A test fixture, example placeholder, mock value, comment, or documentation snippet

Respond ONLY with valid JSON in this exact shape:
{
  "is_real_secret": <bool>,
  "reasoning": "<one sentence>",
  "evidence": [
    {"file": "<path>", "line": <int>, "snippet": "<verbatim from code>", "kind": "secret" | "context"}
  ]
}

Consider: file path (under tests/, fixtures/, docs/, examples/), surrounding identifiers
("example", "test", "fake", "mock", "dummy", "placeholder"), value shape (obvious placeholder
like "xxx", "abc123", "your-key-here"), and the credential pattern itself.

Every snippet must be copy-pasted verbatim. Never invent file paths or line numbers."""

SKEPTIC_SYSTEM_SECRET = """You are a skeptical reviewer of the hunter's secret assessment.

If the hunter said is_real_secret=true, look for evidence it's a fake/test value.
If the hunter said is_real_secret=false, look for evidence it's actually a real leak.

Respond ONLY with valid JSON in this exact shape:
{
  "agree_with_hunter": <bool>,
  "counter_evidence": [
    {"file": "<path>", "line": <int>, "snippet": "<verbatim>", "kind": "test_marker" | "doc_marker" | "real_indicator"}
  ],
  "reasoning": "<one sentence>"
}

Positive evidence required to disagree. Absence is not disagreement."""


def hunter_secret_user_message(finding: dict, code_context: str) -> str:
    return (
        f"Candidate secret:\n"
        f"  detector: {finding.get('detector_name', finding.get('rule', ''))}\n"
        f"  file: {finding.get('file')}\n"
        f"  line: {finding.get('line')}\n"
        f"  verified_by_provider: {finding.get('verified', False)}\n"
        f"  matched value (redacted last chars shown): "
        f"{(finding.get('redacted_match') or finding.get('match','')[:6] + '…')[:20]}\n"
        f"\n"
        f"Code context:\n```\n{code_context}\n```\n"
    )


def skeptic_secret_user_message(finding: dict, hunter_verdict: dict, code_context: str) -> str:
    return (
        f"Candidate secret at {finding.get('file')}:{finding.get('line')}\n"
        f"\n"
        f"Hunter said is_real_secret={hunter_verdict.get('is_real_secret')}: "
        f"{hunter_verdict.get('reasoning', '')}\n"
        f"\n"
        f"Code context:\n```\n{code_context}\n```\n"
    )
