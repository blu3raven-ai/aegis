"""Additive premium SBOM match against the hosted Argus vulnerability DB.

After the free OSV-mirror match, the backend optionally matches the same SBOM
components against Argus's premium advisory DB over the org's existing Argus
connection (the one that also routes verification). Premium hits are returned as
raw finding dicts in the *same* nested shape the free OSV match produces, so they
flow through the identical advisory-enrichment + lifecycle ingest path.

This is purely additive and best-effort: when Argus is unconfigured, disabled,
unreachable, or returns garbage, this module returns an empty list so the free
matches always ship regardless.
"""
from __future__ import annotations

import logging

import httpx

from src.osv.matcher import ComponentRef
from src.settings.argus.service import (
    ArgusAuthError,
    ArgusConnectionDTO,
    mint_argus_access_token,
)

logger = logging.getLogger(__name__)

_MATCH_TIMEOUT = 30.0


def _references(raw_refs: object) -> list[dict]:
    refs: list[dict] = []
    if isinstance(raw_refs, list):
        for ref in raw_refs:
            if isinstance(ref, dict) and ref.get("url"):
                refs.append({"url": ref["url"]})
    return refs


def _finding_from_match(match: dict) -> dict | None:
    """Map one Argus premium match to the raw finding shape ``_build_raw_finding``
    emits. Returns None for malformed entries so a bad row never aborts the batch.

    The ``repository`` / image identity is left blank here — the caller stamps it
    from the scoped asset's ``external_ref`` so lifecycle resolves the same asset.
    """
    if not isinstance(match, dict):
        return None
    pkg = match.get("package") or {}
    advisory = match.get("advisory") or {}
    if not isinstance(pkg, dict) or not isinstance(advisory, dict):
        return None

    name = pkg.get("name")
    version = match.get("version")
    advisory_id = advisory.get("id")
    if not name or not version or not advisory_id:
        return None

    first_patched = advisory.get("first_patched_version")
    return {
        "repository": {"name": "", "full_name": ""},
        "dependency": {
            "package": {"name": name, "ecosystem": pkg.get("ecosystem")},
            "manifest_path": match.get("manifest_path") or "",
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


async def match_via_argus(
    conn: ArgusConnectionDTO | None,
    components: list[ComponentRef],
    *,
    asset_id: str,
    surface: str,
) -> list[dict]:
    """Match SBOM components against the Argus premium DB.

    Returns raw finding dicts (same shape as the free OSV match) for premium hits,
    marked ``source``/``match_source`` = ``"argus"``. Returns ``[]`` when Argus is
    unconfigured, disabled, unreachable, or errors — the free matches always ship
    regardless.
    """
    if conn is None or not conn.enabled or not components:
        return []

    # Mint a fresh short-lived bearer; the durable refresh token never leaves the
    # backend. A mint failure degrades to free-only — it never aborts the scan.
    try:
        token = mint_argus_access_token(conn)
    except ArgusAuthError as exc:
        logger.warning("argus match: token mint failed: %s", exc)
        return []

    url = f"{conn.endpoint.rstrip('/')}/v1/match"
    body = {
        "surface": surface,
        "components": [{"purl": c.purl, "version": c.version} for c in components],
    }
    try:
        async with httpx.AsyncClient(timeout=_MATCH_TIMEOUT) as client:
            resp = await client.post(
                url, json=body, headers={"Authorization": f"Bearer {token}"}
            )
    except httpx.HTTPError as exc:
        logger.warning("argus match: endpoint unreachable: %s", type(exc).__name__)
        return []

    if resp.status_code != 200:
        logger.warning("argus match: non-200 response: HTTP %s", resp.status_code)
        return []

    try:
        matches = resp.json().get("matches")
    except ValueError:
        logger.warning("argus match: response was not valid JSON")
        return []
    if not isinstance(matches, list):
        return []

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
