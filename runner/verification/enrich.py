"""Copy audit-report-grade fields from a confirmed hunter result into metadata.

Shared by the SAST pipeline and the SCA/IaC verifiers so the enrichment stays
consistent: reproduction outline, multiple attack paths, and mitigating factors.
These ride in verification_metadata (no schema change) and only for confirmed
findings — surfacing them on an unverified finding would overstate confidence.
"""
from __future__ import annotations

from typing import Any


def stash_confirmed_enrichment(metadata: dict[str, Any], hunter_model: Any) -> None:
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
