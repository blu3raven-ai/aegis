"""Normalize Grype JSON output to findings JSONL for container scanning.

Port of scanners/container/scripts/normalize-container.py — keeps the exact
byte-level finding shape so downstream ingestion remains stable."""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _extract_ghsa_id(match: dict) -> str | None:
    vid = match.get("vulnerability", {}).get("id", "")
    if vid.startswith("GHSA-"):
        return vid
    for rel in match.get("relatedVulnerabilities", []) or []:
        if rel.get("id", "").startswith("GHSA-"):
            return rel["id"]
    return None


def _extract_cve_id(match: dict) -> str | None:
    vid = match.get("vulnerability", {}).get("id", "")
    if vid.startswith("CVE-"):
        return vid
    for rel in match.get("relatedVulnerabilities", []) or []:
        if rel.get("id", "").startswith("CVE-"):
            return rel["id"]
    return None


def _max_cvss(match: dict) -> float | None:
    scores: list[float] = []
    for c in match.get("vulnerability", {}).get("cvss", []) or []:
        s = c.get("metrics", {}).get("baseScore")
        if s is not None:
            scores.append(float(s))
    return max(scores) if scores else None


def _split_image_ref(image_ref: str) -> tuple[str, str]:
    """Return (image_name, image_tag) from a raw image reference.

    Matches the bash original behaviour: if the ref has a ":" but isn't a bare
    digest, split on the last ":". Otherwise tag defaults to "latest"."""
    if ":" in image_ref and not image_ref.startswith("sha256:"):
        name, tag = image_ref.rsplit(":", 1)
        return name, tag
    return image_ref, "latest"


def normalize_file(
    file_path: Path,
    org: str,
    image_ref: str,
    image_digest: str = "",
) -> list[dict]:
    """Parse a single grype.json file into a list of normalized finding dicts."""
    with open(file_path) as f:
        data = json.load(f)

    image_name, image_tag = _split_image_ref(image_ref)

    findings: list[dict] = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})

        ghsa_id = _extract_ghsa_id(match)
        cve_id = _extract_cve_id(match)
        advisory_id = ghsa_id or cve_id or vuln.get("id", "")

        fix_versions = fix.get("versions", []) or []
        first_patched = fix_versions[0] if fix_versions else None

        locations = artifact.get("locations", []) or []
        manifest_path = locations[0].get("path", "") if locations else ""

        finding = {
            "organization": org,
            "repository": image_name,
            "source": "container",
            "commitSha": image_digest,
            "packageName": artifact.get("name", ""),
            "packageVersion": artifact.get("version", ""),
            "manifestPath": manifest_path,
            "ecosystem": artifact.get("type", ""),
            "advisoryId": advisory_id,
            "ghsaId": ghsa_id,
            "cveId": cve_id,
            "severity": (vuln.get("severity") or "unknown").lower(),
            "cvssScore": _max_cvss(match),
            "fixedVersion": first_patched,
            "fixState": fix.get("state", "unknown"),
            "vulnerableVersionRange": vuln.get("versionConstraint", ""),
            "publishedDate": vuln.get("publishedDate"),
            "lastModifiedDate": vuln.get("modifiedDate"),
            "summary": (vuln.get("description") or "")[:200],
            "description": vuln.get("description", ""),
            "references": [{"url": u} for u in vuln.get("urls", []) or []],
            "scanner": "grype",
            "stateCandidate": "open",
            "imageName": image_name,
            "imageTag": image_tag,
            "imageDigest": image_digest,
        }
        findings.append(finding)

    return findings


def normalize_grype_output(
    org: str,
    target_dir: Path,
) -> tuple[int, int]:
    """Walk target_dir for per-image findings.json files and write findings.jsonl.

    For each ``<target_dir>/<safe_name>/findings.json``, look up the matching
    ``sbom.cdx.json`` and ``digest.txt`` (mirrors the for-loop at the bottom of
    scanners/container/run.sh) and emit one normalized line per match.

    Returns (total_findings, error_count)."""
    target = Path(target_dir)
    findings_file = target / "findings.jsonl"

    total = 0
    errors = 0
    with open(findings_file, "w") as out:
        for raw_file in sorted(target.rglob("findings.json")):
            image_dir = raw_file.parent
            sbom_path = image_dir / "sbom.cdx.json"
            if not sbom_path.exists():
                continue

            image_ref = _read_image_ref_from_sbom(sbom_path)
            image_digest = ""
            digest_file = image_dir / "digest.txt"
            if digest_file.exists():
                image_digest = digest_file.read_text().strip()

            try:
                for f in normalize_file(raw_file, org, image_ref, image_digest):
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:  # noqa: BLE001
                errors += 1
                logger.warning("[!] Failed to normalize %s: %s", raw_file, e)

    logger.info(
        "[+] Normalized %d container findings (%d errors) -> %s",
        total,
        errors,
        findings_file,
    )
    return total, errors


def _read_image_ref_from_sbom(sbom_path: Path) -> str:
    """Read .metadata.component.name from a CycloneDX SBOM. Falls back to "unknown".

    Mirrors the ``jq -r '.metadata.component.name // "unknown"'`` in run.sh."""
    try:
        data = json.loads(sbom_path.read_text())
    except (json.JSONDecodeError, OSError):
        return "unknown"
    return (data.get("metadata") or {}).get("component", {}).get("name") or "unknown"
