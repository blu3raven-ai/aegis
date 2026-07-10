"""Prompts for the container CVE enrichment verifier.

No source repo or image is available at verify-time — only the advisory + package
+ image metadata. The model's job is enrichment: name the vector, state the impact,
outline attack paths / reproduction / mitigating factors, and propose a fix. It is
NOT asked to judge reachability (the package's mere presence in the image is the
only signal, handled deterministically by the backend verdict fuse).
"""
from __future__ import annotations

CONTAINER_ENRICH_SYSTEM = (
    "You are a container security analyst. Given a CVE affecting a package "
    "installed in a container image, explain what an attacker achieves and how to "
    "fix it. You have only the advisory and package/image metadata — no source "
    "code and no running container — so do NOT claim to trace code paths. Respond "
    "with strict JSON matching the schema. Base every claim on the advisory; do "
    "not invent file citations."
)


def container_enrich_user_message(finding: dict, advisory_context: str) -> str:
    pkg = finding.get("packageName") or finding.get("package") or ""
    version = finding.get("packageVersion") or finding.get("version") or ""
    cve = finding.get("cve") or finding.get("cveId") or finding.get("advisoryId") or ""
    image = finding.get("imageName") or ""
    tag = finding.get("imageTag") or ""
    return (
        f"CVE: {cve}\n"
        f"Package: {pkg} {version}\n"
        f"Image: {image}:{tag}\n\n"
        f"Advisory:\n{advisory_context}\n\n"
        "Produce JSON with: exploit_chain (how the vuln is exploited in a "
        "container context), title (specific vector), impact (one sentence: what "
        "the attacker achieves), reproduction (high-level steps, no weaponised "
        "payload), attack_paths (list of {name, steps}), mitigating_factors "
        "(list), fix (upgrade guidance or 1-3 sentences). evidence may be an empty "
        "list — you have no code to cite."
    )
