"""Per-finding IaC (checkov) verification."""
from __future__ import annotations

import logging
from pathlib import Path

from runner.verification.pipeline import VerificationResult
from runner.verification.prompts.iac import (
    HUNTER_SYSTEM_IAC,
    SKEPTIC_SYSTEM_IAC,
    _read_resource_excerpt,
    hunter_iac_user_message,
    skeptic_iac_user_message,
)
from runner.verification.schemas.verdict import HunterResponse, SkepticResponse

logger = logging.getLogger(__name__)


_HUNTER_MAX_TOKENS = 900
_SKEPTIC_MAX_TOKENS = 400

# Sibling-context budget — IaC modules often contain dozens of small files; cap
# total bytes fed to the LLM to keep latency and cost bounded.
_SIBLING_MAX_FILES = 6
_SIBLING_MAX_BYTES_PER_FILE = 2_000
_SIBLING_MAX_TOTAL_BYTES = 8_000

# Sibling files we treat as IaC context. Anything else (vendored binaries,
# generated lockfiles) is skipped.
_IAC_EXTENSIONS = (".tf", ".tfvars", ".yaml", ".yml", ".json", ".hcl")
_IAC_FILENAMES = ("Dockerfile", "dockerfile")


def _collect_sibling_excerpt(repo_root: str, file_path: str) -> str:
    """Return a bounded text excerpt of sibling IaC files in the same directory.

    The hunter / skeptic need to see neighbouring resources (attachments, policies,
    listeners, data sources) to reason about compensating controls without
    introducing a dedicated repo-traversal tool.
    """
    try:
        root = Path(repo_root).resolve()
    except OSError:
        return ""

    # Refuse to read anything that resolves outside repo_root — protects against
    # `../` traversal in scanner output and symlinks pointing outside the clone.
    try:
        target = (root / file_path).resolve()
    except OSError:
        return ""
    if not target.is_relative_to(root):
        return ""

    parent = target.parent if target.parent.exists() else root

    parts: list[str] = []
    total = 0
    files = 0
    for sibling in sorted(parent.iterdir()):
        if files >= _SIBLING_MAX_FILES:
            break
        try:
            resolved = sibling.resolve()
        except OSError:
            continue
        if not resolved.is_relative_to(root):
            continue
        if not sibling.is_file() or resolved == target:
            continue
        if sibling.suffix not in _IAC_EXTENSIONS and sibling.name not in _IAC_FILENAMES:
            continue
        try:
            text = sibling.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not text.strip():
            continue
        snippet = text[:_SIBLING_MAX_BYTES_PER_FILE]
        rel = resolved.relative_to(root).as_posix()
        block = f"--- {rel} ---\n{snippet}"
        if total + len(block) > _SIBLING_MAX_TOTAL_BYTES:
            break
        parts.append(block)
        total += len(block)
        files += 1

    return "\n\n".join(parts)


def verify_iac_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    escalation_llm=None,
    accepted_risks: list | None = None,
    ground_truth=None,
) -> VerificationResult:
    """Hunter -> Skeptic for a single IaC (checkov) misconfiguration finding.

    No mechanical citation critic for v1: IaC evidence cites resource blocks and
    sibling context within the same module rather than the kind of file:line
    source citations the SAST/SCA critic was built for. Hunter narrative +
    skeptic compensating-control check is sufficient for ``confirmed``; schema
    failures fall back to ``needs_verify``.

    ``escalation_llm`` is the optional frontier tier. When it is ``None`` (no
    escalation model configured) the flow is identical to the single-tier path.
    Escalation retries only the hunter on a *schema* failure — the default tier
    couldn't emit a valid exploit chain — so a stronger model gets one recall
    shot at producing a verdict the default tier failed to produce.
    ``verification_metadata["tier"]`` records which tier drove the verdict and
    ``["escalated"]`` marks that escalation fired.
    """
    tokens_in = 0
    tokens_out = 0
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "scanner": "iac_scanning",
        "tier": "default",
    }

    file_path = finding.get("file", "")
    line = int(finding.get("line", 1) or 1)
    resource_excerpt = _read_resource_excerpt(repo_root, file_path, line)
    sibling_excerpt = _collect_sibling_excerpt(repo_root, file_path)

    hunter_messages = [
        {"role": "system", "content": HUNTER_SYSTEM_IAC},
        {
            "role": "user",
            "content": hunter_iac_user_message(
                finding, resource_excerpt, sibling_excerpt
            ),
        },
    ]

    # The tier the rest of the verification runs on; escalation promotes it.
    active_llm = llm

    hunter_result = active_llm.chat_json(
        hunter_messages,
        HunterResponse,
        temperature=0.0,
        max_tokens=_HUNTER_MAX_TOKENS,
    )
    tokens_in += hunter_result.tokens_in
    tokens_out += hunter_result.tokens_out
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
        hunter_result = active_llm.chat_json(
            hunter_messages,
            HunterResponse,
            temperature=0.0,
            max_tokens=_HUNTER_MAX_TOKENS,
        )
        tokens_in += hunter_result.tokens_in
        tokens_out += hunter_result.tokens_out
        metadata["prompt_hashes"].extend(hunter_result.prompt_hashes)

    if hunter_result.parsed is None:
        logger.warning(
            "iac hunter response failed schema validation: %s — falling back",
            hunter_result.error,
        )
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain="",
            evidence=[],
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {hunter_result.error}"},
        )
    hunter_model = hunter_result.parsed
    chain = hunter_model.exploit_chain.strip()
    evidence = hunter_model.evidence

    if not chain:
        metadata["reason"] = "hunter_no_chain"
        return VerificationResult(
            verdict="possible",
            exploit_chain="",
            evidence=evidence,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata=metadata,
        )

    skeptic_result = active_llm.chat_json(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM_IAC},
            {
                "role": "user",
                "content": skeptic_iac_user_message(
                    finding, chain, resource_excerpt, sibling_excerpt,
                    accepted_risks=accepted_risks, ground_truth=ground_truth,
                ),
            },
        ],
        SkepticResponse,
        temperature=0.0,
        max_tokens=_SKEPTIC_MAX_TOKENS,
    )
    tokens_in += skeptic_result.tokens_in
    tokens_out += skeptic_result.tokens_out
    metadata["prompt_hashes"].extend(skeptic_result.prompt_hashes)

    if skeptic_result.parsed is None:
        logger.warning(
            "iac skeptic response failed schema validation: %s — falling back",
            skeptic_result.error,
        )
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain=chain,
            evidence=evidence,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata={**metadata, "reason": f"skeptic_schema_invalid: {skeptic_result.error}"},
        )
    skeptic_model = skeptic_result.parsed

    from runner.verification.carveouts import carveout_verdict
    from runner.verification.critic import verify_citations
    _cv = carveout_verdict(
        finding, skeptic_model, accepted_risks=accepted_risks,
        chain=chain, evidence=evidence, metadata=metadata,
        critic=verify_citations, repo_root=repo_root,
        tokens_in=tokens_in, tokens_out=tokens_out,
    )
    if _cv is not None:
        return _cv

    if skeptic_model.mitigation_found:
        metadata["ruled_out_reason"] = {
            "file": skeptic_model.mitigation_file,
            "line": skeptic_model.mitigation_line,
            "snippet": skeptic_model.mitigation_snippet,
            "reasoning": skeptic_model.reasoning,
        }
        if not (skeptic_model.mitigation_snippet or "").strip():
            metadata["suppression_downgraded"] = "empty_mitigation_citation"
            return VerificationResult(
                verdict="needs_verify",
                exploit_chain=chain,
                evidence=evidence,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                verification_metadata=metadata,
            )
        return VerificationResult(
            verdict="ruled_out",
            exploit_chain=chain,
            evidence=evidence,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata=metadata,
        )

    # Confirmed chain — surface the enriched audit detail the hunter gave.
    from runner.verification.enrich import stash_confirmed_enrichment
    stash_confirmed_enrichment(metadata, hunter_model, repo_root=repo_root)

    return VerificationResult(
        verdict="confirmed",
        exploit_chain=chain,
        evidence=evidence,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        verification_metadata=metadata,
    )
