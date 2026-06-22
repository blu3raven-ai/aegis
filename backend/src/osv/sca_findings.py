"""Build canonical dependency/container findings from OSV matches.

Given an asset's indexed SBOM components, match them against the OSV mirror and
materialise findings in the nested shape the existing lifecycle hooks and
advisory enricher already consume. This is what lets the backend produce
SCA + container findings from an SBOM alone, without the runner performing any
vulnerability matching.

The identifying fields (repository / image) are derived from the asset's own
``external_ref`` so that ``canonical_external_ref`` in the lifecycle hooks
resolves back to the *same* asset — no duplicate asset rows.
"""
from __future__ import annotations

import json
import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import OsvAdvisory, SbomComponent
from src.osv.matcher import ComponentRef, VulnMatch, match_components, parse_purl
from src.osv.store import _download_blob

logger = logging.getLogger(__name__)

_SEVERITY_WORD = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def _cve_from_aliases(body: dict) -> str | None:
    for alias in body.get("aliases") or []:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            return alias
    return None


def _cvss_vector(body: dict) -> str | None:
    for sev in body.get("severity") or []:
        if isinstance(sev, dict) and sev.get("score"):
            return sev["score"]
    return None


def _severity_level(body: dict) -> str:
    """Best-effort severity word from an OSV advisory body.

    OSV stores a CVSS *vector* (not a number) under ``severity``; the human
    level lives in ``database_specific.severity`` for GHSA-sourced advisories.
    Numeric CVSS is left to the downstream NVD/GHSA enricher.
    """
    ds = body.get("database_specific") or {}
    word = ds.get("severity")
    if isinstance(word, str) and word.upper() in _SEVERITY_WORD:
        return _SEVERITY_WORD[word.upper()]
    return "unknown"


def _references(body: dict) -> list[dict]:
    refs = []
    for ref in body.get("references") or []:
        if isinstance(ref, dict) and ref.get("url"):
            refs.append({"url": ref["url"]})
    return refs


def _vulnerable_range_str(match: VulnMatch) -> str:
    """Human-readable affected range from the matched interval."""
    intro = match.introduced if match.introduced and match.introduced != "0" else None
    parts = []
    if intro:
        parts.append(f">= {intro}")
    if match.fixed:
        parts.append(f"< {match.fixed}")
    elif match.last_affected:
        parts.append(f"<= {match.last_affected}")
    return ", ".join(parts) if parts else "all versions"


def _build_raw_finding(
    *,
    kind: str,
    repo_name: str,
    repo_full_name: str,
    image_name: str | None,
    image_tag: str | None,
    comp: ComponentRef,
    match: VulnMatch,
    adv_body: dict,
) -> dict:
    """Assemble one finding in the nested shape the lifecycle hooks parse."""
    cve_id = _cve_from_aliases(adv_body)
    raw: dict = {
        "repository": {"name": repo_name, "full_name": repo_full_name},
        "dependency": {
            "package": {"name": comp.name, "ecosystem": match.ecosystem},
            "manifest_path": "",
        },
        "security_advisory": {
            # OSV advisory id holds the ghsa_id slot so identity is stable for
            # any advisory source (GHSA / PYSEC / DSA / CVE).
            "ghsa_id": match.advisory_id,
            "cve_id": cve_id,
            "severity": _severity_level(adv_body),
            "cvss": {"score": None, "vector_string": _cvss_vector(adv_body)},
            "summary": adv_body.get("summary", ""),
            "description": adv_body.get("details", ""),
            "html_url": "",
            "references": _references(adv_body),
            "published_at": adv_body.get("published", ""),
        },
        "security_vulnerability": {
            "vulnerable_version_range": _vulnerable_range_str(match),
            "first_patched_version": {"identifier": match.fixed} if match.fixed else None,
        },
        "current_version": comp.version,
        "source": "backend_match",
        "scanner": "osv",
        "matched_by": ["osv"],
        "match_source": "backend_match",
    }
    if kind == "container":
        raw["imageName"] = image_name
        raw["imageTag"] = image_tag or "latest"
    return raw


def _parse_repo_external_ref(external_ref: str) -> tuple[str, str]:
    """``github:owner/repo`` -> (repo_name, full_name) = ("repo", "owner/repo")."""
    _st, rest = external_ref.split(":", 1)
    full = rest
    name = rest.split("/", 1)[-1]
    return name, full


def _parse_image_external_ref(external_ref: str) -> tuple[str, str]:
    """``ghcr:owner/img:tag`` -> (image_name, tag) = ("owner/img", "tag")."""
    _st, rest = external_ref.split(":", 1)
    if ":" in rest:
        name, tag = rest.rsplit(":", 1)
        return name, tag
    return rest, "latest"


async def build_backend_match_findings(
    session: AsyncSession,
    *,
    asset_id: str,
    external_ref: str,
    kind: str,
) -> list[dict]:
    """Match one asset's SBOM components against OSV and build raw findings.

    ``kind`` is "dependencies" or "container". Returns raw finding dicts ready
    for advisory enrichment + apply_lifecycle. Pure data — no subprocess.
    """
    rows = (
        await session.execute(
            select(SbomComponent).where(SbomComponent.asset_id == asset_id)
        )
    ).scalars().all()
    if not rows:
        return []

    components: list[ComponentRef] = []
    comp_purl: dict[ComponentRef, str] = {}
    for r in rows:
        purl_type, namespace = parse_purl(r.purl)
        # Fall back to the stored ecosystem when the purl carries no type.
        ref = ComponentRef(
            name=r.name,
            version=r.version,
            purl_type=purl_type or (r.ecosystem or ""),
            namespace=namespace,
        )
        components.append(ref)
        comp_purl[ref] = r.purl

    matched = await match_components(session, components)
    if not matched:
        return []

    if kind == "container":
        image_name, image_tag = _parse_image_external_ref(external_ref)
        repo_name, repo_full = image_name, image_name
    else:
        repo_name, repo_full = _parse_repo_external_ref(external_ref)
        image_name = image_tag = None

    # Fetch advisory bodies once per distinct advisory.
    advisory_ids = {m.advisory_id for ms in matched.values() for m in ms}
    headers = (
        await session.execute(
            select(OsvAdvisory).where(OsvAdvisory.advisory_id.in_(advisory_ids))
        )
    ).scalars().all()
    bodies: dict[str, dict] = {}
    for h in headers:
        try:
            blob = _download_blob(h.blob_key)
            bodies[h.advisory_id] = json.loads(blob) if blob else {}
        except Exception:
            logger.warning("osv: failed to read advisory body %s", h.advisory_id)
            bodies[h.advisory_id] = {}

    findings: list[dict] = []
    for comp, matches in matched.items():
        for m in matches:
            findings.append(
                _build_raw_finding(
                    kind=kind,
                    repo_name=repo_name,
                    repo_full_name=repo_full,
                    image_name=image_name,
                    image_tag=image_tag,
                    comp=comp,
                    match=m,
                    adv_body=bodies.get(m.advisory_id, {}),
                )
            )
    return findings
