"""Per-finding SCA verification."""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from runner.verification.critic import verify_citations
from runner.verification.helpers.import_sites import find_import_sites
from runner.verification.llm_client import LlmResponse
from runner.verification.pipeline import VerificationResult
from runner.verification.prompts.sca import (
    HUNTER_SYSTEM_SCA,
    SKEPTIC_SYSTEM_SCA,
    hunter_sca_user_message,
    skeptic_sca_user_message,
)
from runner.verification.schemas.verdict import HunterResponse, SkepticResponse

logger = logging.getLogger(__name__)


_MAX_IMPORT_SITES = 5
_HUNTER_MAX_TOKENS = 900
_SKEPTIC_MAX_TOKENS = 400


def verify_sca_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    critic: Callable[[list[dict], str], tuple[list[str], list[str]]] = verify_citations,
    import_sites: list[dict] | None = None,
    max_import_sites: int = _MAX_IMPORT_SITES,
) -> VerificationResult:
    """Hunter → Skeptic → Critic for a single SCA finding."""
    tokens_in = 0
    tokens_out = 0
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "scanner": "dependencies",
    }

    advisory_detail = finding.get("advisoryDetail") or None
    manifest_excerpt = finding.get("manifestSnippet") or ""

    if import_sites is None:
        package_name = finding.get("packageName", "")
        ecosystem = finding.get("ecosystem", "")
        if package_name and ecosystem:
            sites = find_import_sites(
                Path(repo_root), package_name, ecosystem, max_sites=max_import_sites
            )
            import_sites = [s.to_dict() for s in sites]
        else:
            import_sites = []
    metadata["import_site_count"] = len(import_sites)

    hunter_resp: LlmResponse = llm.chat(
        [
            {"role": "system", "content": HUNTER_SYSTEM_SCA},
            {
                "role": "user",
                "content": hunter_sca_user_message(
                    finding, advisory_detail, import_sites, manifest_excerpt
                ),
            },
        ],
        temperature=0.0,
        max_tokens=_HUNTER_MAX_TOKENS,
    )
    tokens_in += hunter_resp.tokens_in
    tokens_out += hunter_resp.tokens_out
    metadata["prompt_hashes"].append(hunter_resp.prompt_hash)

    try:
        hunter_model = HunterResponse.model_validate_json(hunter_resp.content)
        chain = hunter_model.exploit_chain.strip()
        evidence = hunter_model.evidence
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "sca hunter response failed schema validation: %s — falling back",
            exc,
        )
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain="",
            evidence=[],
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {exc}"},
        )

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

    skeptic_resp = llm.chat(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM_SCA},
            {
                "role": "user",
                "content": skeptic_sca_user_message(
                    finding, chain, advisory_detail, import_sites, manifest_excerpt
                ),
            },
        ],
        temperature=0.0,
        max_tokens=_SKEPTIC_MAX_TOKENS,
    )
    tokens_in += skeptic_resp.tokens_in
    tokens_out += skeptic_resp.tokens_out
    metadata["prompt_hashes"].append(skeptic_resp.prompt_hash)

    try:
        skeptic_model = SkepticResponse.model_validate_json(skeptic_resp.content)
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "sca skeptic response failed schema validation: %s — falling back",
            exc,
        )
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain=chain,
            evidence=evidence,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata={**metadata, "reason": f"skeptic_schema_invalid: {exc}"},
        )

    if skeptic_model.mitigation_found:
        metadata["ruled_out_reason"] = {
            "file": skeptic_model.mitigation_file,
            "line": skeptic_model.mitigation_line,
            "snippet": skeptic_model.mitigation_snippet,
            "reasoning": skeptic_model.reasoning,
        }
        return VerificationResult(
            verdict="ruled_out",
            exploit_chain=chain,
            evidence=evidence,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            verification_metadata=metadata,
        )

    unverified, _ = critic(evidence, repo_root)
    if unverified:
        metadata["unverified_citations"] = unverified
        verdict = "needs_verify"
    else:
        verdict = "confirmed"

    # Only surface the reproduction outline once the chain is confirmed.
    if verdict == "confirmed" and hunter_model.reproduction.strip():
        metadata["reproduction"] = hunter_model.reproduction.strip()

    return VerificationResult(
        verdict=verdict,
        exploit_chain=chain,
        evidence=evidence,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        verification_metadata=metadata,
    )
