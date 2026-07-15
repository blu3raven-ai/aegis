"""Scope-match declared accepted-risks against a single finding.

A risk with no scope keys applies to every finding on the source. Any provided
scope key (path_glob / rule_id / scanner) must match for the risk to apply; keys
combine with AND. Pure function — no LLM, no I/O — so the match is deterministic
and auditable before the skeptic ever confirms applicability.
"""
from __future__ import annotations

import fnmatch
from typing import Any


def _finding_rule(finding: dict[str, Any]) -> str:
    return str(finding.get("rule") or finding.get("rule_id") or finding.get("check_id") or "")


def accepted_risks_for_finding(
    finding: dict[str, Any], accepted_risks: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    if not accepted_risks:
        return []
    path = str(finding.get("file") or finding.get("file_path") or "")
    rule = _finding_rule(finding)
    scanner = str(finding.get("scanner") or "")
    matched: list[dict[str, Any]] = []
    for risk in accepted_risks:
        glob = risk.get("path_glob")
        if glob and not fnmatch.fnmatch(path, str(glob)):
            continue
        if risk.get("rule_id") and str(risk["rule_id"]) != rule:
            continue
        if risk.get("scanner") and str(risk["scanner"]) != scanner:
            continue
        matched.append(risk)
    return matched


def carveout_verdict(
    finding: dict[str, Any],
    skeptic: Any,
    *,
    accepted_risks: list[dict[str, Any]] | None,
    chain: str,
    evidence: list[Any],
    metadata: dict[str, Any],
    critic,
    repo_root: str,
    tokens_in: int,
    tokens_out: int,
):
    """Apply the tiered ground-truth carve-out to a resolved skeptic result.

    Shared by the SCA and IaC verifiers (the SAST path keeps its own inline copy).
    Returns a ``VerificationResult`` when a carve-out decides the verdict —
    user-declared (authoritative, and only for a risk that was actually provided)
    → ``ruled_out``; a grounded baseline → ``needs_verify`` (downgrade only). An
    ungrounded baseline claim is discarded AND ``skeptic.mitigation_found`` is
    cleared so the caller's mitigation block doesn't re-consume the same citation.
    Returns ``None`` when no carve-out applies, so the caller continues its own
    mitigation/verdict flow unchanged.
    """
    from runner.verification.pipeline import VerificationResult

    matched = accepted_risks_for_finding(finding, accepted_risks)
    declared_ids = {str(r.get("id")) for r in matched}

    if (
        skeptic.carve_out_matched
        and skeptic.carve_out_source == "accepted_risk"
        and str(skeptic.carve_out_ref) in declared_ids
    ):
        risk = next(r for r in matched if str(r.get("id")) == str(skeptic.carve_out_ref))
        metadata["ruled_out_reason"] = {
            "source": "accepted_risk",
            "risk_id": str(risk.get("id")),
            "statement": risk.get("statement"),
            "reasoning": skeptic.reasoning,
        }
        return VerificationResult(
            verdict="ruled_out", exploit_chain=chain, evidence=evidence,
            tokens_in=tokens_in, tokens_out=tokens_out, verification_metadata=metadata,
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
                tokens_in=tokens_in, tokens_out=tokens_out, verification_metadata=metadata,
            )
        # Ungrounded baseline → discard; the skeptic's mitigation fields ARE that
        # ungrounded citation, so clear the flag to keep the caller's mitigation
        # block from re-consuming them.
        skeptic.mitigation_found = False

    return None
