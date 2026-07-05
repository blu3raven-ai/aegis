"""Additive premium SBOM match against the in-process premium advisory store.

After the free OSV-mirror match, the backend optionally matches the same SBOM
components against the premium advisory store. Premium hits are returned as raw
finding dicts in the *same* nested shape the free OSV match produces, so they
flow through the identical advisory-enrichment + lifecycle ingest path.

This is purely additive: the premium store is an empty placeholder today, so it
returns nothing and the free matches always ship regardless.
"""
from __future__ import annotations

import logging

from src.osv.matcher import ComponentRef
from src.osv.premium_match import MatchComponent, MatchItem, match_components

logger = logging.getLogger(__name__)


def _references(raw_refs: object) -> list[dict]:
    refs: list[dict] = []
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append({"url": ref["url"]})
    return refs


def _finding_from_match(match: MatchItem) -> dict | None:
    """Map one premium ``MatchItem`` to the raw finding shape ``_build_raw_finding``
    emits. Returns None for malformed entries so a bad row never aborts the batch.

    The ``MatchItem`` is dumped to a dict first so the mapping stays identical to
    the wire-era shape (keeping downstream ingest/dedup byte-for-byte unchanged).
    The ``repository`` / image identity is left blank here — the caller stamps it
    from the scoped asset's ``external_ref`` so lifecycle resolves the same asset.
    """
    data = match.model_dump()
    pkg = data.get("package") or {}
    advisory = data.get("advisory") or {}
    if not isinstance(pkg, dict) or not isinstance(advisory, dict):
        return None

    name = pkg.get("name")
    version = data.get("version")
    advisory_id = advisory.get("id")
    if not name or not version or not advisory_id:
        return None

    first_patched = advisory.get("first_patched_version")
    return {
        "repository": {"name": "", "full_name": ""},
        "dependency": {
            "package": {"name": name, "ecosystem": pkg.get("ecosystem")},
            "manifest_path": data.get("manifest_path") or "",
        },
        "security_advisory": {
            "ghsa_id": advisory_id,
            "cve_id": advisory.get("cve_id"),
            "severity": advisory.get("severity") or "unknown",
            "cvss": {
                "score": advisory.get("cvss_score"),
                "vector_string": advisory.get("cvss_vector"),
            },
            "summary": advisory.get("summary", ""),
            "description": advisory.get("description", ""),
            "html_url": advisory.get("html_url", ""),
            "references": _references(advisory.get("references")),
            "published_at": advisory.get("published_at", ""),
        },
        "security_vulnerability": {
            "vulnerable_version_range": advisory.get("vulnerable_version_range", ""),
            "first_patched_version": (
                {"identifier": first_patched} if first_patched else None
            ),
        },
        "current_version": version,
        "source": "argus",
        "scanner": "osv",
        "matched_by": ["argus"],
        "match_source": "argus",
    }


def match_via_argus(
    components: list[ComponentRef],
    *,
    asset_id: str,
    surface: str,
) -> list[dict]:
    """Match SBOM components against the premium advisory store, in-process.

    Returns raw finding dicts (same shape as the free OSV match) for premium hits,
    marked ``source``/``match_source`` = ``"argus"``. Returns ``[]`` when there
    are no components or no premium hits — the free matches always ship regardless.
    """
    if not components:
        return []

    # Only purl + version are supplied, matching the previous wire body — the
    # matcher derives the ecosystem and package name from the purl.
    match_components_in = [
        MatchComponent(purl=c.purl, version=c.version) for c in components
    ]
    matches = match_components(surface, match_components_in)

    findings: list[dict] = []
    for match in matches:
        finding = _finding_from_match(match)
        if finding is not None:
            findings.append(finding)
    if findings:
        logger.info(
            "argus match: %d premium hit(s) for asset %s", len(findings), asset_id
        )
    return findings
