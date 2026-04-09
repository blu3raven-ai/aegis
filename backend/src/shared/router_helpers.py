"""Shared router helpers used across all scanning tool API routers.

Contains org parsing dependency, scope filtering, error responses, and
finding slimming for Grype-based tools (SCA + Container).
"""
from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException, Query, Request
from fastapi.responses import JSONResponse

from src.settings.team_access import actor_user_id, user_has_repository_access
from src.settings.router import has_permission
from src.settings.organisations_store import list_teams
from src.settings.direct_access_store import list_direct_grants
from src.shared.paths import parse_org_values


def require_orgs(org: list[str] = Query(default_factory=list)) -> list[str]:
    """FastAPI dependency that parses and validates the org query parameter.

    Usage: `orgs: list[str] = Depends(require_orgs)`
    """
    orgs = parse_org_values(org)
    if not orgs:
        raise HTTPException(status_code=400, detail="Missing org parameter")
    return orgs


def filter_by_user_scope(
    request: Request,
    items: list[dict[str, Any]],
    org_key: str = "organization",
    repo_key: str = "repository",
) -> list[dict[str, Any]]:
    """Filter items by user's repository access scope.

    Workspace admins see everything. Other users only see items
    for repositories they have access to via team membership or direct grants.
    """
    if has_permission(request, "manage_access_scope"):
        return items
    user_id = actor_user_id(request)
    teams = list_teams()
    direct_grants = list_direct_grants()
    return [
        item for item in items
        if user_has_repository_access(
            teams, user_id,
            str(item.get(org_key) or ""),
            str(item.get(repo_key) or ""),
            direct_grants=direct_grants,
        )
    ]


def _extract_grype_full_name(finding: dict[str, Any]) -> str:
    """Extract full_name from Grype-based finding (SCA/Container): repository.full_name."""
    repo = finding.get("repository") or {}
    return repo.get("full_name", "") if isinstance(repo, dict) else ""


def _extract_code_scanning_full_name(finding: dict[str, Any]) -> str:
    """Extract full_name from Code Scanning finding: repo_full_name."""
    return finding.get("repo_full_name", "")


def filter_findings_by_scope(
    request: Request,
    findings: list[dict[str, Any]],
    full_name_fn: Callable[[dict[str, Any]], str] = _extract_grype_full_name,
) -> list[dict[str, Any]]:
    """Filter findings by user scope using a full_name extractor.

    Findings store org/repo as a combined "org/repo" string in different
    locations depending on the tool. The full_name_fn extracts it:
    - Grype (SCA/Container): finding["repository"]["full_name"]
    - Code Scanning: finding["repo_full_name"]

    Splits the full_name on "/" to get org and repo for access checks.
    Workspace admins bypass filtering entirely.
    """
    if has_permission(request, "manage_access_scope"):
        return findings
    user_id = actor_user_id(request)
    teams = list_teams()
    direct_grants = list_direct_grants()
    filtered: list[dict[str, Any]] = []
    for finding in findings:
        full_name = full_name_fn(finding)
        if not full_name or "/" not in full_name:
            continue
        r_org, r_repo = full_name.split("/", 1)
        if user_has_repository_access(teams, user_id, r_org, r_repo, direct_grants=direct_grants):
            filtered.append(finding)
    return filtered


def validate_org(org: str) -> None:
    """Validate that the org exists in source connections. Raises 403 if not."""
    from src.shared.config import get_orgs_from_source_connections
    valid_orgs = get_orgs_from_source_connections()
    if org not in valid_orgs:
        raise HTTPException(status_code=403, detail="Access denied to org")


def api_error(message: str, status_code: int) -> JSONResponse:
    """Return a JSON error response."""
    return JSONResponse({"error": message}, status_code=status_code)


def slim_grype_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Strip a Grype-based finding to frontend-safe shape.

    Used by SCA and Container scanning. Code Scanning has its own slimming function
    since its finding schema is different.
    """
    advisory = finding.get("security_advisory") or {}
    vuln = finding.get("security_vulnerability") or {}
    dep = finding.get("dependency") or {}
    pkg = dep.get("package") or {}
    repo = finding.get("repository") or {}
    cvss = advisory.get("cvss") or {}
    vuln_pkg = vuln.get("package") or {}
    references = advisory.get("references")
    safe_references = references if isinstance(references, list) else []

    return {
        "number": finding.get("number"),
        "state": finding.get("state"),
        "current_version": finding.get("current_version"),
        "commit_sha": finding.get("commit_sha"),
        "dependency": {
            "package": {"ecosystem": pkg.get("ecosystem", ""), "name": pkg.get("name", "")},
            "manifest_path": dep.get("manifest_path", ""),
            "scope": dep.get("scope"),
        },
        "security_advisory": {
            "ghsa_id": advisory.get("ghsa_id", ""),
            "cve_id": advisory.get("cve_id"),
            "summary": advisory.get("summary", ""),
            "description": advisory.get("description", ""),
            "severity": advisory.get("severity", ""),
            "cvss": {"score": cvss.get("score"), "vector_string": cvss.get("vector_string")} if isinstance(cvss, dict) else {"score": cvss, "vector_string": None},
            "published_at": advisory.get("published_at", ""),
            "updated_at": advisory.get("updated_at", ""),
            "references": safe_references,
        },
        "security_vulnerability": {
            "package": {"ecosystem": vuln_pkg.get("ecosystem", ""), "name": vuln_pkg.get("name", "")},
            "severity": vuln.get("severity", ""),
            "vulnerable_version_range": vuln.get("vulnerable_version_range", ""),
            "first_patched_version": vuln.get("first_patched_version"),
        },
        "url": finding.get("url", ""),
        "html_url": finding.get("html_url", ""),
        "created_at": finding.get("created_at", ""),
        "updated_at": finding.get("updated_at", ""),
        "dismissed_at": finding.get("dismissed_at"),
        "dismissed_by": finding.get("dismissed_by"),
        "dismissed_reason": finding.get("dismissed_reason"),
        "dismissed_comment": finding.get("dismissed_comment"),
        "fixed_at": finding.get("fixed_at"),
        "state_changed_at": finding.get("state_changed_at"),
        "first_seen_at": finding.get("first_seen_at"),
        "repository": {
            "id": repo.get("id"),
            "name": repo.get("name", ""),
            "full_name": repo.get("full_name", ""),
            "html_url": repo.get("html_url", ""),
            "private": repo.get("private", False),
        },
        "source": finding.get("source", "git"),
        "scanner": finding.get("scanner", "grype"),
        "matched_by": finding.get("matched_by", []),
        "manifest_snippet": finding.get("manifest_snippet"),
        "manifest_match_line": finding.get("manifest_match_line"),
    }
