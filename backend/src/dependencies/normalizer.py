"""Transform Grype JSON output into the finding dict format expected by the lifecycle engine."""
from __future__ import annotations

from typing import Any

from src.shared.grype import extract_ghsa_id, extract_cve_id, max_cvss_score


def _extract_ghsa_id_sca(vuln: dict[str, Any]) -> str:
    return extract_ghsa_id(vuln.get("id", ""), vuln.get("aliases") or []) or vuln.get("id", "")


def _extract_cve_id_sca(vuln: dict[str, Any]) -> str | None:
    return extract_cve_id(vuln.get("id", ""), vuln.get("aliases") or [])


def _max_cvss_score_sca(vuln: dict[str, Any]) -> float | None:
    return max_cvss_score(vuln.get("cvss") or [])


def normalize_grype_output(
    grype_json: dict[str, Any],
    org: str,
    repo: str,
    commit_sha: str,
    source_label: str,
) -> list[dict[str, Any]]:
    """Convert Grype JSON matches into finding dicts matching the SCA alert schema."""
    findings: list[dict[str, Any]] = []
    repo_name = repo.rsplit("/", 1)[-1] if "/" in repo else repo

    for match in grype_json.get("matches") or []:
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        locations = artifact.get("locations") or []
        manifest_path = locations[0]["path"] if locations else ""
        fix_versions = (vuln.get("fix") or {}).get("versions") or []
        fix_version = fix_versions[0] if fix_versions else None
        severity = (vuln.get("severity") or "unknown").lower()
        cvss_score = _max_cvss_score_sca(vuln)
        ghsa_id = _extract_ghsa_id_sca(vuln)
        cve_id = _extract_cve_id_sca(vuln)
        data_source = vuln.get("dataSource") or ""

        finding: dict[str, Any] = {
            "state": "open",
            "source": "git",
            "scanner": "grype",
            "matched_by": [source_label],
            "commit_sha": commit_sha,
            "current_version": artifact.get("version"),
            "repository": {"name": repo_name, "full_name": repo},
            "dependency": {
                "package": {
                    "name": artifact.get("name", ""),
                    "ecosystem": artifact.get("type", ""),
                },
                "manifest_path": manifest_path,
            },
            "security_advisory": {
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "summary": vuln.get("description", ""),
                "description": vuln.get("description", ""),
                "severity": severity,
                "cvss": {"score": cvss_score, "vector_string": None},
                "published_at": "",
                "updated_at": "",
                "html_url": data_source,
                "references": [{"url": data_source}] if data_source else [],
            },
            "security_vulnerability": {
                "package": {
                    "name": artifact.get("name", ""),
                    "ecosystem": artifact.get("type", ""),
                },
                "severity": severity,
                "vulnerable_version_range": "",
                "first_patched_version": {"identifier": fix_version} if fix_version else None,
            },
            "manifest_snippet": None,
            "manifest_match_line": None,
        }
        findings.append(finding)

    return findings
