#!/usr/bin/env python3
"""Normalize Grype output to findings JSONL."""
import json
import logging
import re
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def normalize_file(file_path: Path, org: str, repo: str, commit: str, manifests_dir: Path | None) -> list[dict]:
    with open(file_path) as f:
        data = json.load(f)

    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        locations = artifact.get("locations", [])
        manifest_path = locations[0].get("path", "") if locations else ""
        cvss_scores = [c.get("metrics", {}).get("baseScore", 0) for c in (vuln.get("cvss") or [])]
        fix_versions = vuln.get("fix", {}).get("versions", [])
        data_source = vuln.get("dataSource", "")

        finding = {
            "organization": org,
            "repository": repo,
            "source": "git",
            "commitSha": commit,
            "packageName": artifact.get("name", ""),
            "packageVersion": artifact.get("version", ""),
            "manifestPath": manifest_path,
            "ecosystem": artifact.get("type", ""),
            "advisoryId": vuln.get("id", ""),
            "advisoryAliases": vuln.get("aliases", []),
            "severity": (vuln.get("severity") or "unknown").lower(),
            "cvssScore": max(cvss_scores) if cvss_scores else None,
            "fixedVersion": fix_versions[0] if fix_versions else None,
            "fixState": vuln.get("fix", {}).get("state", "unknown"),
            "summary": vuln.get("description", ""),
            "description": vuln.get("description", ""),
            "references": [{"url": data_source}] if data_source else [],
            "scanner": "grype",
            "stateCandidate": "open",
            "manifestSnippet": None,
            "manifestMatchLine": None,
        }

        # Enrich with manifest snippet
        # Grype paths are root-relative (e.g. "/requirements.txt"); manifests are saved
        # without the leading slash, so strip it before the lookup.
        if manifests_dir and manifests_dir.exists() and manifest_path and finding["packageName"]:
            clean_path = manifest_path.lstrip("/")
            safe_name = clean_path.replace("/", "__")
            mf = manifests_dir / safe_name
            if mf.exists():
                try:
                    lines = mf.read_text(errors="replace").splitlines()
                    pkg = finding["packageName"].lower()
                    pkg_re = re.compile(r"(?i)(?<![a-zA-Z0-9._-])" + re.escape(pkg) + r"(?![a-zA-Z0-9._-])")
                    match_line = next((i for i, l in enumerate(lines, 1) if pkg_re.search(l)), 0)
                    if match_line:
                        start = max(0, match_line - 8)
                        finding["manifestSnippet"] = "\n".join(lines[start:match_line + 7])
                        finding["manifestMatchLine"] = match_line
                    else:
                        finding["manifestSnippet"] = "\n".join(lines[:15])
                except Exception:
                    pass

        findings.append(finding)

    return findings


def main():
    org, target_dir, run_id = sys.argv[1], sys.argv[2], sys.argv[3]
    target = Path(target_dir)
    # Scanner writes to $OUTDIR/$repo_name/findings.json directly
    raw_dir = target
    # Legacy path: $OUTDIR/runs/$RUN_ID/raw/ — fall back if present
    legacy_dir = target / "runs" / run_id / "raw"
    if legacy_dir.is_dir() and any(legacy_dir.rglob("findings.json")):
        raw_dir = legacy_dir
    findings_file = target / "findings.jsonl"

    total = 0
    errors = 0
    with open(findings_file, "w") as out:
        for raw_file in sorted(raw_dir.rglob("findings.json")):
            repo_dir = raw_file.parent
            repo = str(repo_dir.relative_to(raw_dir))
            commit = "HEAD"
            sha_file = repo_dir / "head-sha.txt"
            if sha_file.exists():
                commit = sha_file.read_text().strip() or "HEAD"
            try:
                for f in normalize_file(raw_file, org, repo, commit, repo_dir / "manifests"):
                    out.write(json.dumps(f, separators=(",", ":")) + "\n")
                    total += 1
            except Exception as e:
                errors += 1
                logger.warning("[!] Failed: %s — %s", repo, e)

    logger.info("[✓] Normalized %d SCA findings (%d errors) → %s", total, errors, findings_file)


if __name__ == "__main__":
    main()
