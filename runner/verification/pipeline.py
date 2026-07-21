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

from runner.scanners._context import resolve_in_root
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

    def __post_init__(self) -> None:
        # Surface token spend into metadata so the backend usage ledger
        # (record_usage_from_findings) can sum it per scan. Scanners copy
        # verification_metadata onto the finding; without this the totals live
        # only on the result object and never reach the ledger, so Insights
        # shows zero usage despite real LLM calls.
        self.verification_metadata["tokens_in"] = self.tokens_in
        self.verification_metadata["tokens_out"] = self.tokens_out


def _read_code_context(file_path: str, line: int, repo_root: str, *, window: int = 40) -> str:
    # Jail the path to the repo: file_path can originate from finding data that
    # traces back to attacker-controlled source, so an escape (../../, absolute)
    # must not read off the runner host. resolve_in_root returns None on escape.
    full = resolve_in_root(repo_root, file_path)
    if full is None:
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
        temperature=0.0, max_tokens=3000,
    )


def run_fp_detection(
    finding: dict, chain: str, code_context: str, *, llm,
    accepted_risks: list | None = None, ground_truth=None,
):
    """FP-detection chain (skeptic): look for a grounded upstream mitigation, and
    match the finding against declared accepted-risks / baseline ground truth."""
    return llm.chat_json(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM},
            {"role": "user", "content": skeptic_user_message(
                finding, chain, code_context,
                accepted_risks=accepted_risks, ground_truth=ground_truth,
            )},
        ],
        SkepticResponse,
        temperature=0.0, max_tokens=1000,
    )


def verify_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    escalation_llm=None,
    accepted_risks: list | None = None,
    ground_truth=None,
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

    from runner.verification.carveouts import accepted_risks_for_finding
    matched_risks = accepted_risks_for_finding(finding, accepted_risks)
    declared_ids = {str(r.get("id")) for r in matched_risks}

    # Findings arrive with either (file, line) [semgrep path] or
    # (file_path, start_line) [SARIF normalize path]. The normalize path
    # already attaches a code_window read from source, so prefer it; only
    # fall back to a disk read when no window was attached. Without this,
    # the SARIF-path finding has file=None and the hunter sees
    # "// not readable" — every verdict degrades to hunter_no_chain.
    code_context = (
        finding.get("code_window")
        or _read_code_context(
            finding.get("file") or finding.get("file_path") or "",
            int(finding.get("line") or finding.get("start_line") or 1),
            repo_root,
        )
    )

    # Reachability lives at the top level of the runner finding (set by the
    # code_scanning normalizer from the call-graph analysis). Reading it from
    # `detail` silently dropped it, so the hunter ran with no reachability
    # signal and had to re-infer reachability from the code window alone.
    reachability = finding.get("reachability") or (finding.get("detail") or {}).get("reachability") or None

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
    skeptic_result = run_fp_detection(
        finding, chain, code_context, llm=active_llm,
        accepted_risks=matched_risks, ground_truth=ground_truth,
    )
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

    # Tiered ground-truth carve-out. User-declared is authoritative but only for a
    # risk that was actually provided (the LLM can confirm, not invent). Baseline is
    # advisory: it can only downgrade, and only once its citation is grounded.
    if skeptic.carve_out_matched and skeptic.carve_out_source == "accepted_risk" \
            and str(skeptic.carve_out_ref) in declared_ids:
        risk = next(r for r in matched_risks if str(r.get("id")) == str(skeptic.carve_out_ref))
        metadata["ruled_out_reason"] = {
            "source": "accepted_risk",
            "risk_id": str(risk.get("id")),
            "statement": risk.get("statement"),
            "reasoning": skeptic.reasoning,
        }
        return VerificationResult(
            verdict="ruled_out", exploit_chain=chain, evidence=evidence,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata=metadata,
        )

    if skeptic.carve_out_matched and skeptic.carve_out_source == "baseline":
        baseline_evidence = [{
            "kind": "code",
            "file": skeptic.mitigation_file or "",
            "line": skeptic.mitigation_line or 0,
            "snippet": skeptic.mitigation_snippet or "",
        }]
        unverified, _ = critic(baseline_evidence, repo_root)
        if not unverified:
            metadata["carve_out_source"] = "baseline"
            metadata["carve_out_ref"] = skeptic.carve_out_ref
            metadata["suppression_downgraded"] = ["baseline_match"]
            return VerificationResult(
                verdict="needs_verify", exploit_chain=chain, evidence=evidence,
                tokens_in=tokens_in_total, tokens_out=tokens_out_total,
                verification_metadata=metadata,
            )
        # Ungrounded baseline claim → discard it entirely. The skeptic's mitigation
        # fields ARE the ungrounded baseline citation, so don't let the mitigation
        # block re-consume them — fall through to the normal (confirmed) flow.
        skeptic.mitigation_found = False

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

    # Enriched audit-report detail (repro, attack paths, mitigating factors) only
    # once the chain is confirmed — surfacing it on an unverified finding overstates it.
    if verdict == "confirmed":
        from runner.verification.enrich import stash_confirmed_enrichment
        stash_confirmed_enrichment(metadata, hunter_model, repo_root=repo_root)

        # "confirmed IF <question>": a grounded chain that hinges on a runtime fact
        # the model couldn't check statically. Carry the exact check instead of a
        # flat confirmed. Enrichment above still applies — it's a real finding.
        question = (getattr(hunter_model, "runtime_question", "") or "").strip()
        if getattr(hunter_model, "needs_runtime", False) and question:
            verdict = "needs_runtime_verification"
            metadata["runtime_question"] = question
            evidence = [*evidence, {"kind": "runtime_log", "snippet": question, "source": "runtime_check"}]

    return VerificationResult(
        verdict=verdict, exploit_chain=chain, evidence=evidence,
        tokens_in=tokens_in_total, tokens_out=tokens_out_total,
        verification_metadata=metadata,
    )
