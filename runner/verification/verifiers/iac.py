"""Per-finding IaC (checkov) verification."""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic import ValidationError

from runner.verification.llm_client import LlmResponse
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
) -> VerificationResult:
    """Hunter -> Skeptic for a single IaC (checkov) misconfiguration finding.

    No mechanical citation critic for v1: IaC evidence cites resource blocks and
    sibling context within the same module rather than the kind of file:line
    source citations the SAST/SCA critic was built for. Hunter narrative +
    skeptic compensating-control check is sufficient for ``confirmed``; schema
    failures fall back to ``needs_verify``.
    """
    tokens_in = 0
    tokens_out = 0
    metadata: dict = {
        "model": getattr(llm, "_model", "unknown"),
        "prompt_hashes": [],
        "scanner": "iac_scanning",
    }

    file_path = finding.get("file", "")
    line = int(finding.get("line", 1) or 1)
    resource_excerpt = _read_resource_excerpt(repo_root, file_path, line)
    sibling_excerpt = _collect_sibling_excerpt(repo_root, file_path)

    hunter_resp: LlmResponse = llm.chat(
        [
            {"role": "system", "content": HUNTER_SYSTEM_IAC},
            {
                "role": "user",
                "content": hunter_iac_user_message(
                    finding, resource_excerpt, sibling_excerpt
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
            "iac hunter response failed schema validation: %s — falling back",
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
            {"role": "system", "content": SKEPTIC_SYSTEM_IAC},
            {
                "role": "user",
                "content": skeptic_iac_user_message(
                    finding, chain, resource_excerpt, sibling_excerpt
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
            "iac skeptic response failed schema validation: %s — falling back",
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

    return VerificationResult(
        verdict="confirmed",
        exploit_chain=chain,
        evidence=evidence,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        verification_metadata=metadata,
    )
