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

from src.db.models import OsvAdvisory, Sbom, SbomComponent
from src.osv.argus_match import match_via_argus
from src.osv.matcher import (
    ComponentRef, VulnMatch, match_components, parse_purl, parse_purl_distro,
)
from src.osv.ecosystems import osv_release_ecosystem
from src.osv.malicious import is_malicious_advisory
from src.osv.severity import severity_word_from_osv_body
from src.osv.store import _download_blob
from src.settings.argus.service import fetch_argus_connection

logger = logging.getLogger(__name__)

# The org's single Argus threat-intel enrichment connection is keyed under the
# default config slot.
_ARGUS_CONFIG_KEY = "default"


def _dedup_key(finding: dict) -> tuple[str | None, str | None, str | None]:
    """Identity used to keep a premium hit from duplicating a free finding.

    Component identity (package name + current version, falling back to purl) plus
    advisory identity (the OSV/GHSA id slot, falling back to CVE). A premium hit
    that already exists in the free set is dropped; the free finding wins.
    """
    dep = finding.get("dependency") or {}
    pkg = dep.get("package") or {}
    adv = finding.get("security_advisory") or {}
    component = pkg.get("name") or dep.get("purl")
    version = finding.get("current_version")
    advisory = adv.get("ghsa_id") or adv.get("cve_id")
    return (component, version, advisory)

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
    """Severity word from an OSV advisory body, or ``"unknown"`` if undeterminable.

    Reads ``database_specific.severity`` when present, otherwise maps the CVSS
    vector's base score to a band (see ``osv.severity``).
    """
    return severity_word_from_osv_body(body) or "unknown"


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
    match_source: str,
    repo_html_url: str | None = None,
) -> dict:
    """Assemble one finding in the nested shape the lifecycle hooks parse.

    ``match_source`` records how the finding was surfaced — ``"scan"`` (an SBOM
    ingest triggered by a code/image push) or ``"overlay"`` (the scheduled OSV
    rematch firing when a newly published advisory hits existing components).
    """
    cve_id = _cve_from_aliases(adv_body)
    malicious = is_malicious_advisory(match.advisory_id)
    # Malicious packages carry no CVSS and no fix — the package is compromised,
    # so they are always critical and the copy points at removal, not upgrade.
    severity = "critical" if malicious else _severity_level(adv_body)
    summary = adv_body.get("summary", "")
    if malicious and not summary:
        summary = f"Malicious package: {comp.name}"
    raw: dict = {
        "repository": {"name": repo_name, "full_name": repo_full_name},
        "dependency": {
            "package": {"name": comp.name, "ecosystem": match.ecosystem},
            "manifest_path": comp.manifest_path or "",
            "scope": comp.scope,
        },
        "malicious": malicious,
        "security_advisory": {
            # OSV advisory id holds the ghsa_id slot so identity is stable for
            # any advisory source (GHSA / PYSEC / DSA / CVE).
            "ghsa_id": match.advisory_id,
            "cve_id": cve_id,
            "severity": severity,
            "cvss": {"score": None, "vector_string": _cvss_vector(adv_body)},
            "summary": summary,
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
        "match_source": match_source,
        # Repo web URL (self-hosted-aware) captured at SBOM ingest; deep-links the
        # finding to source. None for container SBOMs (image, not a repo).
        "repo_html_url": repo_html_url,
        # Manifest declaration site + code window (git deps only; None otherwise),
        # surfaced by the deps lifecycle as the finding's file/line + code preview.
        "manifest_line": comp.manifest_line,
        "manifest_snippet": comp.manifest_snippet,
        "manifest_snippet_start": comp.manifest_snippet_start,
    }
    if kind == "container":
        raw["imageName"] = image_name
        raw["imageTag"] = image_tag or "latest"
        raw["layerDigest"] = comp.layer_digest
        raw["layerIndex"] = comp.layer_index
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
    match_source: str = "scan",
) -> list[dict]:
    """Match one asset's SBOM components against OSV and build raw findings.

    ``kind`` is "dependencies" or "container". ``match_source`` records how the
    findings were surfaced ("scan" for an SBOM-triggered ingest, "overlay" for
    the scheduled OSV rematch). Returns raw finding dicts ready for advisory
    enrichment + apply_lifecycle. Pure data — no subprocess.
    """
    rows = (
        await session.execute(
            select(SbomComponent).where(SbomComponent.asset_id == asset_id)
        )
    ).scalars().all()
    if not rows:
        return []

    components: list[ComponentRef] = []
    for r in rows:
        purl_type, namespace = parse_purl(r.purl)
        # Fall back to the stored ecosystem when the purl carries no type.
        components.append(
            ComponentRef(
                name=r.name,
                version=r.version,
                purl_type=purl_type or (r.ecosystem or ""),
                namespace=namespace,
                release_ecosystem=osv_release_ecosystem(parse_purl_distro(r.purl)),
                purl=r.purl,
                manifest_path=r.manifest_path,
                manifest_line=r.manifest_line,
                manifest_snippet=r.manifest_snippet,
                manifest_snippet_start=r.manifest_snippet_start,
                scope=r.scope,
                layer_digest=r.layer_digest,
                layer_index=r.layer_index,
            )
        )

    matched = await match_components(session, components)

    if kind == "container":
        image_name, image_tag = _parse_image_external_ref(external_ref)
        repo_name, repo_full = image_name, image_name
    else:
        repo_name, repo_full = _parse_repo_external_ref(external_ref)
        image_name = image_tag = None

    # Repo web URL captured at SBOM ingest, for deep-linking the finding to
    # source. Only repos have one; container images don't.
    repo_html_url = None
    if kind != "container":
        repo_html_url = (
            await session.execute(select(Sbom.html_url).where(Sbom.asset_id == asset_id))
        ).scalar_one_or_none()

    findings: list[dict] = []
    if matched:
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
                        match_source=match_source,
                        repo_html_url=repo_html_url,
                    )
                )

    # Additive premium match: Argus may surface advisories the free OSV mirror
    # missed. Premium only ADDS findings — it never replaces a free one. Gated on
    # the default connection's ``enabled`` flag; the store itself is empty today.
    conn = await fetch_argus_connection(session, _ARGUS_CONFIG_KEY)
    premium = (
        match_via_argus(components, asset_id=asset_id, surface=kind)
        if conn is not None and conn.enabled
        else []
    )
    if premium:
        seen = {_dedup_key(f) for f in findings}
        for pf in premium:
            pf["repository"] = {"name": repo_name, "full_name": repo_full}
            if kind == "container":
                pf["imageName"] = image_name
                pf["imageTag"] = image_tag or "latest"
            key = _dedup_key(pf)
            if key not in seen:
                findings.append(pf)
                seen.add(key)
    return findings
