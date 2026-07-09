"""Per-finding verification: two prompt chains + a mechanical critic.

The verifier splits into two independently-invokable prompt chains with distinct
objectives (a classifier-vs-reasoner separation):

- **TP-reasoning** (`run_tp_reasoning`, the hunter) — recall-oriented: try to build
  a concrete exploit chain from the finding to a sink. Answers "can this be
  exploited?".
- **FP-detection** (`run_fp_detection`, the skeptic) — precision-oriented: look for
  a grounded upstream mitigation that neutralises the exploit chain. Answers "is
  this a false positive?".

`verify_finding` orchestrates them (TP-reasoning -> FP-detection -> mechanical
critic grounding -> verdict) exactly as the previous single linear pass did. The
split is structural — each chain is a named unit that can be tested and, later,
model-tiered independently — and the produced verdicts are unchanged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from runner.verification.critic import verify_citations
from runner.verification.prompts import (
    HUNTER_SYSTEM,
    SKEPTIC_SYSTEM,
    hunter_user_message,
    skeptic_user_message,
)
from runner.verification.schemas.verdict import (
    HunterResponse,
    SkepticResponse,
)

logger = logging.getLogger(__name__)


@dataclass
class VerificationResult:
    verdict: str  # confirmed | needs_verify | possible | ruled_out
    exploit_chain: str
    evidence: list[dict]
    tokens_in: int
    tokens_out: int
    verification_metadata: dict = field(default_factory=dict)


def _read_code_context(file_path: str, line: int, repo_root: str, *, window: int = 40) -> str:
    full = Path(repo_root) / file_path
    if not full.exists():
        return f"// {file_path} not readable"
    try:
        text = full.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"// {file_path} read error"
    lines = text.splitlines()
    start = max(0, line - window // 2)
    end = min(len(lines), line + window // 2)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(start, end))


def run_tp_reasoning(finding: dict, code_context: str, reachability, *, llm):
    """TP-reasoning chain (hunter): try to build a concrete exploit chain.

    Returns the raw ``llm.chat_json`` result (parsed ``HunterResponse`` or ``None``
    on schema failure, plus token counts and prompt hashes). Kept as a standalone
    unit so the reasoning chain can be tested — and later model-tiered — on its own.
    """
    return llm.chat_json(
        [
            {"role": "system", "content": HUNTER_SYSTEM},
            {"role": "user", "content": hunter_user_message(finding, code_context, reachability)},
        ],
        HunterResponse,
        temperature=0.0, max_tokens=800,
    )


def run_fp_detection(finding: dict, chain: str, code_context: str, *, llm):
    """FP-detection chain (skeptic): look for a grounded upstream mitigation.

    Returns the raw ``llm.chat_json`` result (parsed ``SkepticResponse`` or ``None``
    on schema failure, plus token counts and prompt hashes). Standalone so the
    false-positive check can be tested — and later model-tiered — independently of
    the reasoning chain.
    """
    return llm.chat_json(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM},
            {"role": "user", "content": skeptic_user_message(finding, chain, code_context)},
        ],
        SkepticResponse,
        temperature=0.0, max_tokens=400,
    )


def verify_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    escalation_llm=None,
    critic: Callable[[list[dict], str], tuple[list[str], list[str]]] = verify_citations,
) -> VerificationResult:
    """Verify one finding on the default model, escalating to a frontier model
    only when the default tier can't produce a usable exploit-chain schema.

    ``escalation_llm`` is the optional frontier tier. When it is ``None`` (no
    escalation model configured) the flow is identical to the single-tier path.
    ``verification_metadata["tier"]`` records which tier produced the verdict and
    ``["escalated"]`` marks that escalation fired.
    """
    tokens_in_total = 0
    tokens_out_total = 0
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "tier": "default",
    }

    code_context = _read_code_context(
        finding.get("file", ""), int(finding.get("line", 1)), repo_root,
    )

    reachability = (finding.get("detail") or {}).get("reachability") or None

    # The tier the rest of the verification runs on; escalation promotes it.
    active_llm = llm

    # TP-reasoning chain: can this finding be exploited?
    hunter_result = run_tp_reasoning(finding, code_context, reachability, llm=active_llm)
    tokens_in_total += hunter_result.tokens_in
    tokens_out_total += hunter_result.tokens_out
    metadata["prompt_hashes"].extend(hunter_result.prompt_hashes)

    # Escalate a schema failure — not a substantive verdict — to the frontier
    # tier: the default model couldn't emit a valid exploit chain, so a stronger
    # model gets one retry and drives the rest of the verification. Pure recall
    # upside; it can only add a verdict the default tier failed to produce.
    if hunter_result.parsed is None and escalation_llm is not None:
        metadata["escalated"] = True
        metadata["tier"] = "frontier"
        metadata["model"] = getattr(escalation_llm, "_model", "unknown")
        active_llm = escalation_llm
        hunter_result = run_tp_reasoning(finding, code_context, reachability, llm=active_llm)
        tokens_in_total += hunter_result.tokens_in
        tokens_out_total += hunter_result.tokens_out
        metadata["prompt_hashes"].extend(hunter_result.prompt_hashes)

    if hunter_result.parsed is None:
        logger.warning(
            "hunter response failed schema validation: %s — falling back to needs_verify",
            hunter_result.error,
        )
        return VerificationResult(
            verdict="needs_verify", exploit_chain="", evidence=[],
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {hunter_result.error}"},
        )
    hunter_model = hunter_result.parsed
    chain = hunter_model.exploit_chain.strip()
    evidence = hunter_model.evidence

    if not chain:
        return VerificationResult(
            verdict="possible", exploit_chain="", evidence=evidence,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": "hunter_no_chain"},
        )

    # FP-detection chain: is there a grounded mitigation that neutralises it?
    skeptic_result = run_fp_detection(finding, chain, code_context, llm=active_llm)
    tokens_in_total += skeptic_result.tokens_in
    tokens_out_total += skeptic_result.tokens_out
    metadata["prompt_hashes"].extend(skeptic_result.prompt_hashes)

    if skeptic_result.parsed is None:
        logger.warning(
            "sast skeptic response failed schema validation: %s — falling back",
            skeptic_result.error,
        )
        skeptic = SkepticResponse()  # all-default: mitigation_found=False
    else:
        skeptic = skeptic_result.parsed

    if skeptic.mitigation_found:
        metadata["ruled_out_reason"] = {
            "file": skeptic.mitigation_file,
            "line": skeptic.mitigation_line,
            "snippet": skeptic.mitigation_snippet,
            "reasoning": skeptic.reasoning,
        }
        mitigation_evidence = [{
            "kind": "code",
            "file": skeptic.mitigation_file or "",
            "line": skeptic.mitigation_line or 0,
            "snippet": skeptic.mitigation_snippet or "",
        }]
        unverified, _ = critic(mitigation_evidence, repo_root)
        if unverified:
            metadata["suppression_downgraded"] = unverified
            return VerificationResult(
                verdict="needs_verify", exploit_chain=chain, evidence=evidence,
                tokens_in=tokens_in_total, tokens_out=tokens_out_total,
                verification_metadata=metadata,
            )
        return VerificationResult(
            verdict="ruled_out", exploit_chain=chain, evidence=evidence,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata=metadata,
        )

    unverified, _ungrounded = critic(evidence, repo_root)
    if unverified:
        metadata["unverified_citations"] = unverified
        verdict = "needs_verify"
    else:
        verdict = "confirmed"

    # Only surface the reproduction outline once the chain is confirmed — showing
    # repro steps for an unverified finding would overstate confidence.
    if verdict == "confirmed" and hunter_model.reproduction.strip():
        metadata["reproduction"] = hunter_model.reproduction.strip()

    return VerificationResult(
        verdict=verdict, exploit_chain=chain, evidence=evidence,
        tokens_in=tokens_in_total, tokens_out=tokens_out_total,
        verification_metadata=metadata,
    )
