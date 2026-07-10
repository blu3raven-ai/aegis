"""Container CVE enrichment verifier.

No repo clone or running image is available — only advisory + package/image
metadata. The verifier asks the model to author enrichment fields (title, impact,
attack paths, fix) and always returns confirmed when the schema validates, because
reachability is handled deterministically by the backend verdict fuse.
"""
from __future__ import annotations

import logging

from pydantic import ValidationError

from runner.verification.enrich import stash_confirmed_enrichment
from runner.verification.pipeline import VerificationResult
from runner.verification.prompts.container import (
    CONTAINER_ENRICH_SYSTEM,
    container_enrich_user_message,
)
from runner.verification.schemas.verdict import HunterResponse

logger = logging.getLogger(__name__)

_MAX_TOKENS = 1200


def verify_container_finding(*, finding: dict, llm) -> VerificationResult:
    """Enrich a container CVE finding with audit-grade metadata via one LLM call."""
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "scanner": "container_scanning",
    }

    advisory_parts = [
        finding.get("summary") or "",
        finding.get("description") or "",
        finding.get("advisoryDetail") or "",
    ]
    advisory_context = "\n".join(p for p in advisory_parts if p).strip()
    if not advisory_context:
        advisory_context = "(no advisory text available)"

    resp = llm.chat(
        [
            {"role": "system", "content": CONTAINER_ENRICH_SYSTEM},
            {"role": "user", "content": container_enrich_user_message(finding, advisory_context)},
        ],
        temperature=0.0,
        max_tokens=_MAX_TOKENS,
    )
    metadata["prompt_hashes"].append(resp.prompt_hash)

    try:
        hunter_model = HunterResponse.model_validate_json(resp.content)
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "container hunter response failed schema validation: %s — falling back", exc
        )
        return VerificationResult(
            verdict="needs_verify",
            exploit_chain="",
            evidence=[],
            tokens_in=resp.tokens_in,
            tokens_out=resp.tokens_out,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {exc}"},
        )

    stash_confirmed_enrichment(metadata, hunter_model)
    return VerificationResult(
        verdict="confirmed",
        exploit_chain=hunter_model.exploit_chain.strip(),
        evidence=hunter_model.evidence or [],
        tokens_in=resp.tokens_in,
        tokens_out=resp.tokens_out,
        verification_metadata=metadata,
    )
