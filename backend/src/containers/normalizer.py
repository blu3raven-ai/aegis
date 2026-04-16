# backend/src/containers/normalizer.py
"""Normalize Grype JSON output for container image scans."""
from __future__ import annotations

import logging
from typing import Any

from src.shared.grype import extract_ghsa_id, extract_cve_id, max_cvss_score

logger = logging.getLogger(__name__)


def _extract_ghsa_id_container(match: dict) -> str | None:
    vuln = match.get("vulnerability", {})
    return extract_ghsa_id(vuln.get("id", ""), match.get("relatedVulnerabilities", []))


def _extract_cve_id_container(match: dict) -> str | None:
    vuln = match.get("vulnerability", {})
    return extract_cve_id(vuln.get("id", ""), match.get("relatedVulnerabilities", []))


def _max_cvss_score_container(match: dict) -> float | None:
    return max_cvss_score(match.get("vulnerability", {}).get("cvss", []))


def _extract_cvss_vector(vuln: dict) -> str | None:
    """Return the CVSS vector string from the highest-scored entry."""
    best_score = -1.0
    best_vector = None
    for c in vuln.get("vulnerability", {}).get("cvss", []):
        m = c.get("metrics", {})
        s = m.get("baseScore", 0)
        if s > best_score:
            best_score = s
            best_vector = c.get("vector")
    return best_vector


def normalize_grype_output(
    grype_json: dict,
    org: str,
    image_ref: str,
    image_digest: str | None = None,
) -> list[dict[str, Any]]:
    """Convert Grype JSON output to normalized finding dicts.

    Args:
        grype_json: Parsed Grype JSON output (top-level has "matches" array).
        org: Organization label.
        image_ref: Full image reference (e.g. "ghcr.io/org/app:v1").
        image_digest: Image digest (sha256:...) if available.

    Returns:
        List of normalized finding dicts ready for lifecycle processing.
    """
    matches = grype_json.get("matches", [])
    findings: list[dict[str, Any]] = []

    # Split image_ref into name and tag
    if ":" in image_ref and not image_ref.startswith("sha256:"):
        image_name, image_tag = image_ref.rsplit(":", 1)
    else:
        image_name = image_ref
        image_tag = "latest"

    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})

        ghsa_id = _extract_ghsa_id_container(match)
        cve_id = _extract_cve_id_container(match)
        advisory_id = ghsa_id or cve_id or vuln.get("id", "")

        pkg_name = artifact.get("name", "")
        pkg_version = artifact.get("version", "")
        ecosystem = artifact.get("type", "")
        severity = (vuln.get("severity") or "unknown").lower()
        cvss_score = _max_cvss_score_container(match)
        cvss_vector = _extract_cvss_vector(match)

        fix_versions = fix.get("versions", [])
        fix_state = fix.get("state", "unknown")
        first_patched = fix_versions[0] if fix_versions else None

        locations = artifact.get("locations", [])
        manifest_path = locations[0].get("path", "") if locations else ""

        description = vuln.get("description", "")
        data_source = vuln.get("dataSource", "")
        urls = vuln.get("urls", [])
        related = match.get("relatedVulnerabilities", [])

        references: list[dict[str, str]] = [{"url": u} for u in urls]
        for rel in related:
            for u in rel.get("urls", []):
                references.append({"url": u})

        finding = {
            "state": "open",
            "source": "container",
            "scanner": "grype",
            "organization": org,
            "commit_sha": image_digest,
            "current_version": pkg_version,
            "repository": {
                "name": image_name,
                "full_name": image_ref,
            },
            "dependency": {
                "package": {
                    "name": pkg_name,
                    "ecosystem": ecosystem,
                },
                "manifest_path": manifest_path,
            },
            "security_advisory": {
                "ghsa_id": ghsa_id or advisory_id,
                "cve_id": cve_id,
                "summary": description[:200] if description else "",
                "description": description,
                "severity": severity,
                "cvss": cvss_score,
                "cvss_vector": cvss_vector,
                "published_at": vuln.get("publishedDate"),
                "updated_at": vuln.get("modifiedDate"),
                "html_url": data_source,
                "references": references,
            },
            "security_vulnerability": {
                "package": {
                    "name": pkg_name,
                    "ecosystem": ecosystem,
                },
                "severity": severity,
                "vulnerable_version_range": vuln.get("versionConstraint", ""),
                "first_patched_version": (
                    {"identifier": first_patched} if first_patched else None
                ),
            },
            "imageName": image_name,
            "imageTag": image_tag,
            "imageDigest": image_digest,
            "fixState": fix_state,
        }
        findings.append(finding)

    logger.info(
        "Normalized %d Grype matches for image %s",
        len(findings),
        image_ref,
    )
    return findings
