"""Copy audit-report-grade fields from a confirmed hunter result into metadata.

Shared by the SAST pipeline and the SCA/IaC verifiers so the enrichment stays
consistent: reproduction outline, multiple attack paths, and mitigating factors.
These ride in verification_metadata (no schema change) and only for confirmed
findings — surfacing them on an unverified finding would overstate confidence.
"""
from __future__ import annotations

from typing import Any

from runner.verification.cvss import score as cvss_score


def stash_confirmed_enrichment(
    metadata: dict[str, Any], hunter_model: Any, repo_root: str | None = None
) -> None:
    if getattr(hunter_model, "title", "").strip():
        metadata["title"] = hunter_model.title.strip()
    if getattr(hunter_model, "impact", "").strip():
        metadata["impact"] = hunter_model.impact.strip()
    if hunter_model.reproduction.strip():
        metadata["reproduction"] = hunter_model.reproduction.strip()
    paths = [
        p for p in (hunter_model.attack_paths or [])
        if isinstance(p, dict) and str(p.get("steps") or "").strip()
    ]
    if paths:
        metadata["attack_paths"] = paths
    factors = [
        f.strip() for f in (hunter_model.mitigating_factors or [])
        if isinstance(f, str) and f.strip()
    ]
    if factors:
        metadata["mitigating_factors"] = factors
    if getattr(hunter_model, "fix", "").strip():
        metadata["fix"] = hunter_model.fix.strip()
        # Positive-only: badge the fix ONLY when the diff provably applies to the
        # checkout, so an AI-authored patch that references the wrong lines can't
        # be pasted as if it were verified. Unverifiable → simply no badge.
        if repo_root:
            from runner.verification.fix_check import fix_applies

            metadata["fix_verified"] = fix_applies(metadata["fix"], repo_root)

    metrics = getattr(hunter_model, "cvss_metrics", {}) or {}
    scored = cvss_score(metrics) if isinstance(metrics, dict) else None
    if scored is not None:
        vector, base = scored
        metadata["cvss_metrics"] = {k: str(metrics[k]).strip().upper()
                                    for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")}
        metadata["cvss_vector"] = vector
        metadata["cvss_score"] = base

    if getattr(hunter_model, "distinctness", "").strip():
        metadata["distinctness"] = hunter_model.distinctness.strip()

    steps = [s.strip() for s in (getattr(hunter_model, "remediation", []) or [])
             if isinstance(s, str) and s.strip()]
    if steps:
        metadata["remediation"] = steps

    if getattr(hunter_model, "poc_script", "").strip():
        metadata["poc_script"] = hunter_model.poc_script.strip()
        name = (getattr(hunter_model, "poc_filename", "") or "").strip()
        lang = (getattr(hunter_model, "poc_language", "") or "").strip()
        if name:
            metadata["poc_filename"] = name
        if lang:
            metadata["poc_language"] = lang
