"""Base-image recommendation — prove a newer tag has fewer vulnerabilities.

Opt-in and off by default (scanning candidates is a full runner job each). After
a container scan, the strictly-newer same-flavour tags found by the tag listing
(#base-image-tags) are the candidates. This module SBOM-scans the top candidate,
counts its vulnerabilities the same in-memory way as the current image (matched
against the OSV mirror, never persisted as findings — no inventory pollution),
and stores the better tag keyed by the current image digest.

The count is deliberately measured identically for current and candidate so the
delta is honest: both go through ``count_sbom_vulns`` on their own CycloneDX
SBOM, not one from live findings and one in-memory.
"""
from __future__ import annotations

import logging

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def count_sbom_vulns(session: AsyncSession, sbom_cdx: dict) -> int:
    """Count (component, advisory) matches for a CycloneDX SBOM against OSV.

    In-memory only — parses components to matcher inputs and runs the same OSV
    matcher the ingest uses, but never writes findings. Approximates the number
    of findings the image would produce, which is all the comparison needs."""
    from src.osv.ecosystems import osv_release_ecosystem
    from src.osv.matcher import (
        ComponentRef,
        match_components,
        parse_purl,
        parse_purl_distro,
    )

    components = sbom_cdx.get("components") if isinstance(sbom_cdx, dict) else None
    if not isinstance(components, list):
        return 0

    refs: list[ComponentRef] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        name = comp.get("name")
        version = comp.get("version")
        if not name or not version:
            continue
        purl = comp.get("purl") or ""
        purl_type, namespace = parse_purl(purl)
        refs.append(
            ComponentRef(
                name=name,
                version=version,
                purl_type=purl_type or "",
                namespace=namespace,
                release_ecosystem=osv_release_ecosystem(parse_purl_distro(purl)),
                purl=purl,
            )
        )
    if not refs:
        return 0
    matches = await match_components(session, refs)
    return sum(len(v) for v in matches.values())


def pick_recommendation(
    current_count: int, candidate_counts: dict[str, int]
) -> tuple[str, int] | None:
    """Best candidate tag (fewest vulns) that strictly improves on current.

    Returns (tag, count) or None when nothing beats the current image. Ties on
    count break toward the higher tag string (a stable, deterministic choice)."""
    improving = {t: c for t, c in candidate_counts.items() if c < current_count}
    if not improving:
        return None
    best = min(improving.items(), key=lambda tc: (tc[1], _neg_tag(tc[0])))
    return best[0], best[1]


def _neg_tag(tag: str) -> tuple:
    # Sort key helper: for equal counts prefer the lexicographically larger tag.
    return tuple(-ord(c) for c in tag)


def build_candidate_ref(pullable_ref: str, tag: str) -> str:
    """Replace the trailing tag on a pullable image ref.

    ``ghcr.io/acme/app:1.2.3`` + ``2.0.0`` -> ``ghcr.io/acme/app:2.0.0``. The last
    ``:`` is the tag separator (a registry ``host:port`` colon is earlier in the
    ref, so ``rpartition`` splits correctly). Any ``@digest`` is dropped first."""
    ref = pullable_ref.split("@", 1)[0]
    base, sep, _old = ref.rpartition(":")
    # No tag colon after the last "/" means the whole thing is host/repo — append.
    if not sep or "/" in _old:
        return f"{ref}:{tag}"
    return f"{base}:{tag}"
