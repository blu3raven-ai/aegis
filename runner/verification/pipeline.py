"""Per-finding verification: hunter -> skeptic -> mechanical critic."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pydantic import ValidationError

from runner.verification.critic import verify_citations
from runner.verification.llm_client import LlmResponse
from runner.verification.prompts import (
    HUNTER_SYSTEM,
    SKEPTIC_SYSTEM,
    hunter_user_message,
    skeptic_user_message,
)
from runner.verification.prompts import (
    HUNTER_SYSTEM_SECRET,
    SKEPTIC_SYSTEM_SECRET,
    hunter_secret_user_message,
    skeptic_secret_user_message,
)
from runner.verification.schemas.verdict import (
    HunterResponse,
    SecretHunterResponse,
    SecretSkepticResponse,
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


def verify_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    critic: Callable[[list[dict], str], tuple[list[str], list[str]]] = verify_citations,
) -> VerificationResult:
    tokens_in_total = 0
    tokens_out_total = 0
    metadata: dict = {"model": getattr(llm, "_model", "unknown"), "prompt_hashes": []}

    code_context = _read_code_context(
        finding.get("file", ""), int(finding.get("line", 1)), repo_root,
    )

    reachability = (finding.get("detail") or {}).get("reachability") or None

    hunter_resp: LlmResponse = llm.chat(
        [
            {"role": "system", "content": HUNTER_SYSTEM},
            {"role": "user", "content": hunter_user_message(finding, code_context, reachability)},
        ],
        temperature=0.0, max_tokens=800,
    )
    tokens_in_total += hunter_resp.tokens_in
    tokens_out_total += hunter_resp.tokens_out
    metadata["prompt_hashes"].append(hunter_resp.prompt_hash)

    try:
        hunter_model = HunterResponse.model_validate_json(hunter_resp.content)
        chain = hunter_model.exploit_chain.strip()
        evidence = hunter_model.evidence
    except (ValidationError, ValueError) as exc:
        logger.warning("hunter response failed schema validation: %s — falling back to needs_verify", exc)
        return VerificationResult(
            verdict="needs_verify", exploit_chain="", evidence=[],
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {exc}"},
        )

    if not chain:
        return VerificationResult(
            verdict="possible", exploit_chain="", evidence=evidence,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": "hunter_no_chain"},
        )

    skeptic_resp = llm.chat(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM},
            {"role": "user", "content": skeptic_user_message(finding, chain, code_context)},
        ],
        temperature=0.0, max_tokens=400,
    )
    tokens_in_total += skeptic_resp.tokens_in
    tokens_out_total += skeptic_resp.tokens_out
    metadata["prompt_hashes"].append(skeptic_resp.prompt_hash)

    try:
        skeptic = SkepticResponse.model_validate_json(skeptic_resp.content)
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "sast skeptic response failed schema validation: %s — falling back",
            exc,
        )
        skeptic = SkepticResponse()  # all-default: mitigation_found=False

    if skeptic.mitigation_found:
        metadata["ruled_out_reason"] = {
            "file": skeptic.mitigation_file,
            "line": skeptic.mitigation_line,
            "snippet": skeptic.mitigation_snippet,
            "reasoning": skeptic.reasoning,
        }
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

    return VerificationResult(
        verdict=verdict, exploit_chain=chain, evidence=evidence,
        tokens_in=tokens_in_total, tokens_out=tokens_out_total,
        verification_metadata=metadata,
    )


def verify_secret_finding(
    *,
    finding: dict,
    repo_root: str,
    llm,
    critic: Callable[[list[dict], str], tuple[list[str], list[str]]] = verify_citations,
) -> VerificationResult:
    """Verify a candidate secret. Provider-verified secrets are auto-confirmed."""
    metadata: dict = {"model": getattr(llm, "_model", "unknown"), "prompt_hashes": []}

    if finding.get("verified"):
        metadata["auto_confirmed"] = "provider_verified"
        return VerificationResult(
            verdict="confirmed", exploit_chain="", evidence=[],
            tokens_in=0, tokens_out=0,
            verification_metadata=metadata,
        )

    code_context = _read_code_context(
        finding.get("file", ""), int(finding.get("line", 1)), repo_root,
    )

    tokens_in_total = 0
    tokens_out_total = 0

    hunter_resp = llm.chat(
        [
            {"role": "system", "content": HUNTER_SYSTEM_SECRET},
            {"role": "user", "content": hunter_secret_user_message(finding, code_context)},
        ],
        temperature=0.0, max_tokens=400,
    )
    tokens_in_total += hunter_resp.tokens_in
    tokens_out_total += hunter_resp.tokens_out
    metadata["prompt_hashes"].append(hunter_resp.prompt_hash)

    try:
        hunter_model = SecretHunterResponse.model_validate_json(hunter_resp.content)
        is_real = hunter_model.is_real_secret
        evidence = hunter_model.evidence
        hunter_reasoning = hunter_model.reasoning
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "secret hunter response failed schema validation: %s — falling back",
            exc,
        )
        return VerificationResult(
            verdict="needs_verify", exploit_chain="", evidence=[],
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": f"hunter_schema_invalid: {exc}"},
        )

    skeptic_resp = llm.chat(
        [
            {"role": "system", "content": SKEPTIC_SYSTEM_SECRET},
            {"role": "user", "content": skeptic_secret_user_message(
                finding,
                {"is_real_secret": is_real, "reasoning": hunter_reasoning},
                code_context,
            )},
        ],
        temperature=0.0, max_tokens=300,
    )
    tokens_in_total += skeptic_resp.tokens_in
    tokens_out_total += skeptic_resp.tokens_out
    metadata["prompt_hashes"].append(skeptic_resp.prompt_hash)

    try:
        skeptic_model = SecretSkepticResponse.model_validate_json(skeptic_resp.content)
        agrees = skeptic_model.agree_with_hunter
    except (ValidationError, ValueError) as exc:
        logger.warning(
            "secret skeptic response failed schema validation: %s — falling back",
            exc,
        )
        return VerificationResult(
            verdict="needs_verify", exploit_chain=hunter_reasoning, evidence=evidence,
            tokens_in=tokens_in_total, tokens_out=tokens_out_total,
            verification_metadata={**metadata, "reason": f"skeptic_schema_invalid: {exc}"},
        )

    if agrees:
        verdict = "confirmed" if is_real else "ruled_out"
    else:
        verdict = "needs_verify"
        metadata["skeptic_counter_evidence"] = skeptic_model.counter_evidence

    unverified, _ = critic(evidence, repo_root)
    if unverified and verdict == "confirmed":
        metadata["unverified_citations"] = unverified
        verdict = "needs_verify"

    metadata["hunter_reasoning"] = hunter_reasoning
    metadata["skeptic_reasoning"] = skeptic_model.reasoning

    return VerificationResult(
        verdict=verdict, exploit_chain=hunter_reasoning,
        evidence=evidence,
        tokens_in=tokens_in_total, tokens_out=tokens_out_total,
        verification_metadata=metadata,
    )
