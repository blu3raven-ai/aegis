#!/usr/bin/env python3
"""Normalize Grype JSON output to findings JSONL for container scanning."""
import argparse
import json
import sys


def _extract_ghsa_id(match: dict) -> str | None:
    vid = match.get("vulnerability", {}).get("id", "")
    if vid.startswith("GHSA-"):
        return vid
    for rel in match.get("relatedVulnerabilities", []):
        if rel.get("id", "").startswith("GHSA-"):
            return rel["id"]
    return None


def _extract_cve_id(match: dict) -> str | None:
    vid = match.get("vulnerability", {}).get("id", "")
    if vid.startswith("CVE-"):
        return vid
    for rel in match.get("relatedVulnerabilities", []):
        if rel.get("id", "").startswith("CVE-"):
            return rel["id"]
    return None


def _max_cvss(match: dict) -> float | None:
    scores = []
    for c in match.get("vulnerability", {}).get("cvss", []):
        s = c.get("metrics", {}).get("baseScore")
        if s is not None:
            scores.append(float(s))
    return max(scores) if scores else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("findings_json", help="Grype JSON output file")
    parser.add_argument("--org", required=True)
    parser.add_argument("--image-ref", required=True)
    parser.add_argument("--image-digest", default="")
    args = parser.parse_args()

    with open(args.findings_json) as f:
        data = json.load(f)

    image_ref = args.image_ref
    if ":" in image_ref and not image_ref.startswith("sha256:"):
        image_name, image_tag = image_ref.rsplit(":", 1)
    else:
        image_name = image_ref
        image_tag = "latest"

    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        fix = vuln.get("fix", {})

        ghsa_id = _extract_ghsa_id(match)
        cve_id = _extract_cve_id(match)
        advisory_id = ghsa_id or cve_id or vuln.get("id", "")

        fix_versions = fix.get("versions", [])
        first_patched = fix_versions[0] if fix_versions else None

        locations = artifact.get("locations", [])
        manifest_path = locations[0].get("path", "") if locations else ""

        finding = {
            "organization": args.org,
            "repository": image_name,
            "source": "container",
            "commitSha": args.image_digest,
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
            "references": [{"url": u} for u in vuln.get("urls", [])],
            "scanner": "grype",
            "stateCandidate": "open",
            "imageName": image_name,
            "imageTag": image_tag,
            "imageDigest": args.image_digest,
        }
        print(json.dumps(finding))


if __name__ == "__main__":
    main()
