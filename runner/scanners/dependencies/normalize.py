"""Normalize Grype JSON output to findings JSONL.

Port of scanners/dependencies/scripts/normalize-dependencies.py — keeps the
exact byte-level finding shape so downstream ingestion remains stable."""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from runner.scanners.dependencies import advisory_enrichment

logger = logging.getLogger(__name__)


def _enrich_advisories_enabled() -> bool:
    return os.environ.get("AEGIS_DISABLE_EAGER_ENRICHMENT", "").lower() not in (
        "1",
        "true",
        "yes",
    )


def normalize_file(
    file_path: Path,
    org: str,
    repo: str,
    commit: str,
    manifests_dir: Path | None,
) -> list[dict]:
    """Parse a single grype.json file into a list of normalized finding dicts."""
    with open(file_path) as f:
        data = json.load(f)

    findings = []
    for match in data.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        locations = artifact.get("locations", [])
        manifest_path = locations[0].get("path", "") if locations else ""
        cvss_scores = [
            c.get("metrics", {}).get("baseScore", 0) for c in (vuln.get("cvss") or [])
        ]
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

        # Grype paths are root-relative (e.g. "/requirements.txt"); manifests are
        # saved without the leading slash, so strip it before lookup.
        if (
            manifests_dir
            and manifests_dir.exists()
            and manifest_path
            and finding["packageName"]
        ):
            clean_path = manifest_path.lstrip("/")
            safe_name = clean_path.replace("/", "__")
            mf = manifests_dir / safe_name
            if mf.exists():
                try:
                    lines = mf.read_text(errors="replace").splitlines()
                    pkg = finding["packageName"].lower()
                    pkg_re = re.compile(
                        r"(?i)(?<![a-zA-Z0-9._-])"
                        + re.escape(pkg)
                        + r"(?![a-zA-Z0-9._-])"
                    )
                    match_line = next(
                        (i for i, l in enumerate(lines, 1) if pkg_re.search(l)), 0
                    )
                    if match_line:
                        start = max(0, match_line - 8)
                        finding["manifestSnippet"] = "\n".join(
                            lines[start : match_line + 7]
                        )
                        finding["manifestMatchLine"] = match_line
                    else:
                        finding["manifestSnippet"] = "\n".join(lines[:15])
                except Exception:
                    pass

        findings.append(finding)

    return findings


def normalize_grype_output(
    org: str,
    target_dir: Path,
    run_id: str,
) -> tuple[int, int]:
    """Walk target_dir for findings.json files and write aggregated findings.jsonl.

    Returns (total_findings, error_count)."""
    target = Path(target_dir)
    raw_dir = target
    legacy_dir = target / "runs" / run_id / "raw"
    if legacy_dir.is_dir() and any(legacy_dir.rglob("findings.json")):
        raw_dir = legacy_dir
    findings_file = target / "findings.jsonl"

    findings: list[dict] = []
    errors = 0
    for raw_file in sorted(raw_dir.rglob("findings.json")):
        repo_dir = raw_file.parent
        repo = str(repo_dir.relative_to(raw_dir))
        commit = "HEAD"
        sha_file = repo_dir / "head-sha.txt"
        if sha_file.exists():
            commit = sha_file.read_text().strip() or "HEAD"
        try:
            findings.extend(
                normalize_file(
                    raw_file, org, repo, commit, repo_dir / "manifests"
                )
            )
        except Exception as e:
            errors += 1
            logger.warning("[!] Failed: %s - %s", repo, e)

    if _enrich_advisories_enabled() and findings:
        try:
            attach_advisory_details(findings)
        except Exception as e:
            logger.warning("[!] Advisory enrichment failed (non-fatal): %s", e)

    with open(findings_file, "w") as out:
        for f in findings:
            out.write(json.dumps(f, separators=(",", ":")) + "\n")

    total = len(findings)
    logger.info(
        "[✓] Normalized %d SCA findings (%d errors) -> %s",
        total,
        errors,
        findings_file,
    )
    return total, errors


def attach_advisory_details(
    findings: list[dict],
    *,
    cache_dir: Path | None = None,
    nvd_api_key: str | None = None,
) -> None:
    """Fetch advisory text from NVD/OSV and attach as ``advisoryDetail``. Mutates in place."""
    advisory_ids: list[str] = []
    for f in findings:
        if f.get("advisoryId"):
            advisory_ids.append(f["advisoryId"])
        for alias in f.get("advisoryAliases") or []:
            if isinstance(alias, str):
                advisory_ids.append(alias)

    if not advisory_ids:
        return

    api_key = nvd_api_key if nvd_api_key is not None else os.environ.get("NVD_API_KEY")
    details = advisory_enrichment.fetch_advisory_details(
        advisory_ids,
        cache_dir=cache_dir,
        nvd_api_key=api_key,
    )
    if not details:
        return

    for f in findings:
        detail = details.get(f.get("advisoryId", ""))
        if detail is None:
            for alias in f.get("advisoryAliases") or []:
                detail = details.get(alias) if isinstance(alias, str) else None
                if detail is not None:
                    break
        f["advisoryDetail"] = detail.to_dict() if detail else None
