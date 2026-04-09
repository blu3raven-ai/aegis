"""GitHub API client for SCA (Software Composition Analysis).

Ported from lib/github.ts to provide SCA alert fetching (via the
GitHub vulnerability alerts API), SBOM enrichment, and repository
listing for the FastAPI backend.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_GITHUB_API_URL = "https://api.github.com"
MAX_PAGES_PER_REQUEST = 500  # Safety limit to prevent runaway pagination
DEFAULT_PER_PAGE = 100
TIMEOUT_SECONDS = 30.0


class GitHubApiError(Exception):
    """Error from GitHub API with status code."""

    def __init__(self, status: int, body: str = "") -> None:
        self.status = status
        self.body = body
        super().__init__(f"GitHub API error {status}: {body}")


def _github_api_url() -> str:
    return (os.environ.get("GITHUB_API_URL") or DEFAULT_GITHUB_API_URL).rstrip("/")


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _parse_next_link(link_header: str | None) -> str | None:
    """Parse the rel="next" URL from a GitHub Link header."""
    if not link_header:
        return None
    # Link format: <url>; rel="next", <url>; rel="last"
    for part in link_header.split(","):
        if 'rel="next"' in part:
            # Extract URL between < and >
            start = part.find("<")
            end = part.find(">", start + 1)
            if start != -1 and end != -1:
                return part[start + 1 : end]
    return None


@dataclass
class AlertFilters:
    """Filters for SCA vulnerability alerts."""

    state: str | None = None
    severity: str | None = None
    ecosystem: str | None = None
    page: int | None = None
    per_page: int | None = None


def _normalize_ecosystem(ecosystem: str) -> str:
    """Normalize ecosystem names to match SBOM purl types."""
    mapping = {
        "pypi": "pip",
        "gem": "rubygems",
        "golang": "go",
    }
    return mapping.get(ecosystem.lower(), ecosystem.lower())


def _package_key(ecosystem: str, name: str) -> str:
    """Create a lookup key for a package."""
    return f"{_normalize_ecosystem(ecosystem)}:{name.lower()}"


def _parse_purl(purl: str) -> dict[str, str] | None:
    """Parse a package URL (purl) to extract ecosystem and name.

    purl format: pkg:type/namespace/name@version?qualifiers#subpath
    Example: pkg:npm/left-pad@1.3.0
    """
    if not purl.startswith("pkg:"):
        return None

    without_prefix = purl[4:]  # Remove "pkg:"
    slash_index = without_prefix.find("/")
    if slash_index == -1:
        return None

    type_ = without_prefix[:slash_index]
    remainder = without_prefix[slash_index + 1 :].split("?", 1)[0].split("#", 1)[0]

    # Handle version separator
    version_sep = remainder.rfind("@")
    if version_sep != -1:
        encoded_name = remainder[:version_sep]
    else:
        encoded_name = remainder

    return {
        "ecosystem": _normalize_ecosystem(type_),
        "name": encoded_name,  # purl encoding is minimal for package names
    }


def _as_record(value: Any) -> dict[str, Any]:
    """Convert value to a dict if possible, else empty dict."""
    return value if isinstance(value, dict) else {}


async def github_fetch(
    path: str,
    token: str,
    params: dict[str, str] | None = None,
) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch a single page from GitHub API.

    Returns:
        Tuple of (data, link_header)
    """
    url = f"{_github_api_url()}{path}"
    query_params: dict[str, str] = {"per_page": str(DEFAULT_PER_PAGE)}
    if params:
        query_params.update({k: v for k, v in params.items() if v is not None})

    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=_github_headers(token), params=query_params)

    if response.status_code >= 400:
        raise GitHubApiError(response.status_code, response.text)

    data = response.json()
    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) else []

    link_header = response.headers.get("link")
    return data, link_header


async def github_fetch_url(
    url: str,
    token: str,
) -> tuple[list[dict[str, Any]], str | None]:
    """Fetch from a full URL (used for pagination)."""
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=_github_headers(token))

    if response.status_code >= 400:
        raise GitHubApiError(response.status_code, response.text)

    data = response.json()
    if not isinstance(data, list):
        data = [data] if isinstance(data, dict) else []

    link_header = response.headers.get("link")
    return data, link_header


async def fetch_all_pages(
    path: str,
    token: str,
    params: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Fetch all pages of a paginated GitHub endpoint."""
    results: list[dict[str, Any]] = []
    page_data, link_header = await github_fetch(path, token, params)
    results.extend(page_data)

    pages_fetched = 1
    next_url = _parse_next_link(link_header)

    while next_url and pages_fetched < MAX_PAGES_PER_REQUEST:
        page_data, link_header = await github_fetch_url(next_url, token)
        results.extend(page_data)
        next_url = _parse_next_link(link_header)
        pages_fetched += 1

    return results




async def fetch_org_repos(
    org: str,
    token: str,
) -> list[dict[str, Any]]:
    """Fetch all repositories for an organization.

    Args:
        org: GitHub organization name
        token: GitHub personal access token

    Returns:
        List of repository objects with id, name, archived, disabled
    """
    path = f"/orgs/{org}/repos"
    return await fetch_all_pages(path, token, {"type": "all"})


async def fetch_user_orgs(token: str) -> list[dict[str, Any]]:
    """Fetch organizations for the authenticated user.

    Args:
        token: GitHub personal access token

    Returns:
        List of organization objects
    """
    return await fetch_all_pages("/user/orgs", token)


async def fetch_org_teams(org: str, token: str) -> list[dict[str, Any]]:
    """Fetch all teams for an organization.

    Args:
        org: GitHub organization name
        token: GitHub personal access token

    Returns:
        List of team objects with id, name, slug
    """
    path = f"/orgs/{org}/teams"
    return await fetch_all_pages(path, token)


async def fetch_team_members(org: str, team_slug: str, token: str) -> list[dict[str, Any]]:
    """Fetch all members of a team.

    Args:
        org: GitHub organization name
        team_slug: Slug of the team
        token: GitHub personal access token

    Returns:
        List of member objects with login, id
    """
    path = f"/orgs/{org}/teams/{team_slug}/members"
    return await fetch_all_pages(path, token)


async def fetch_team_repositories(org: str, team_slug: str, token: str) -> list[dict[str, Any]]:
    """Fetch all repositories a team has access to.

    Args:
        org: GitHub organization name
        team_slug: Slug of the team
        token: GitHub personal access token

    Returns:
        List of repository objects
    """
    path = f"/orgs/{org}/teams/{team_slug}/repos"
    return await fetch_all_pages(path, token)


async def fetch_org_packages(org: str, token: str, package_type: str = "container") -> list[dict[str, Any]]:
    """Fetch all packages for an organization.

    Args:
        org: GitHub organization name
        token: GitHub personal access token
        package_type: Type of package (default: "container")

    Returns:
        List of package objects
    """
    path = f"/orgs/{org}/packages"
    return await fetch_all_pages(path, token, {"package_type": package_type})


async def fetch_team_packages(org: str, team_slug: str, token: str) -> list[dict[str, Any]]:
    """Fetch all packages a team has access to.
    Note: This uses a newer/preview GitHub API if available, or we might need 
    to iterate packages and check their teams.
    
    Actually, GitHub doesn't have a direct 'teams/packages' endpoint in REST.
    We usually have to check package collaborators or linked repos.
    However, we'll implement this as a placeholder or use the linked repo approach.
    """
    # For now, we'll return an empty list or implement via linked repos if needed.
    # Most GHCR images are linked to a repo.
    return []


async def fetch_repo_collaborators(owner: str, repo: str, token: str) -> list[dict[str, Any]]:
    """Fetch collaborators with direct access to a repository.

    Args:
        owner: Repository owner
        repo: Repository name
        token: GitHub personal access token

    Returns:
        List of collaborator objects with login, id, and permissions
    """
    path = f"/repos/{owner}/{repo}/collaborators"
    # affiliation=direct ensures we only get people added specifically to this repo,
    # not those who have access via team membership.
    return await fetch_all_pages(path, token, {"affiliation": "direct"})


async def check_token_permissions(org: str, token: str) -> dict[str, Any]:
    """Check if the provided token has the required permissions for sync.
    
    Required scopes/permissions:
    - read:org: to list teams and members
    
    Optional capabilities:
    - repo: to list repository collaborators (direct collaborator sync)
    """
    results: dict[str, Any] = {
        "read_org": False,
        "repo_access": False,
        "repo_push": False,
        "capabilities": {
            "direct_collaborator_sync": False,
        }
    }

    # 1. Check read:org by attempting to list teams (minimal check)
    try:
        await fetch_org_teams(org, token)
        results["read_org"] = True
    except GitHubApiError as exc:
        if exc.status in {403, 404}:
            results["read_org"] = False
        else:
            raise

    # 2. Check repo (push) by attempting to list collaborators for a repo
    # We first need to find at least one repo to check
    try:
        repos = await fetch_org_repos(org, token)
        results["repo_access"] = True
        if repos:
            # Check the first repo for collaborator access
            repo_name = repos[0]["name"]
            try:
                await fetch_repo_collaborators(org, repo_name, token)
                results["repo_push"] = True
                results["capabilities"]["direct_collaborator_sync"] = True
            except GitHubApiError as exc:
                if exc.status in {403, 404}:
                    results["repo_push"] = False
                    results["capabilities"]["direct_collaborator_sync"] = False
                else:
                    raise
        else:
            # No repos in org, technically can't verify but we'll mark as pass if we can list repos
            results["repo_push"] = True
            results["capabilities"]["direct_collaborator_sync"] = True
    except GitHubApiError as exc:
        if exc.status in {403, 404}:
            results["repo_access"] = False
            results["repo_push"] = False
            results["capabilities"]["direct_collaborator_sync"] = False
        else:
            raise

    return results


async def fetch_rate_limit(token: str) -> dict[str, Any]:
    """Fetch GitHub API rate limit information for a token."""
    url = f"{_github_api_url()}/rate_limit"
    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        response = await client.get(url, headers=_github_headers(token))

    if response.status_code >= 400:
        raise GitHubApiError(response.status_code, response.text)

    data = response.json()
    resources = _as_record(data).get("resources")
    core = _as_record(resources).get("core")
    if not isinstance(core, dict):
        raise GitHubApiError(502, "Unexpected rate_limit response shape")
    return _as_record(core)


async def fetch_repo_sbom_versions(
    owner: str,
    repo: str,
    token: str,
) -> dict[str, str] | None:
    """Fetch current package versions from repository SBOM.

    Args:
        owner: Repository owner
        repo: Repository name
        token: GitHub personal access token

    Returns:
        Dict mapping package keys to versions, or None if SBOM unavailable
    """
    path = f"/repos/{owner}/{repo}/dependency-graph/sbom"

    try:
        data, _ = await github_fetch(path, token)
    except GitHubApiError as e:
        if e.status in (403, 404):
            return None
        raise

    if not data or not isinstance(data[0], dict):
        return None

    sbom = data[0]
    packages = sbom.get("sbom", {}).get("packages", [])
    if not isinstance(packages, list):
        return None

    versions: dict[str, str] = {}

    for pkg in packages:
        if not isinstance(pkg, dict):
            continue

        external_refs = pkg.get("externalRefs", [])
        if not isinstance(external_refs, list):
            continue

        purl = None
        for ref in external_refs:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purl = ref.get("referenceLocator")
                break

        if not purl:
            continue

        parsed = _parse_purl(purl)
        if parsed and pkg.get("versionInfo"):
            key = _package_key(parsed["ecosystem"], parsed["name"])
            versions[key] = pkg["versionInfo"]

    return versions if versions else None


async def enrich_alerts_with_versions(
    alerts: list[dict[str, Any]],
    token: str,
) -> list[dict[str, Any]]:
    """Enrich alerts with current package versions from SBOM data.

    Args:
        alerts: List of SCA alert objects
        token: GitHub personal access token

    Returns:
        Alerts with added 'current_version' field
    """
    # Group alerts by repository
    by_repo: dict[str, list[dict[str, Any]]] = {}
    for alert in alerts:
        repo_name = _as_record(alert.get("repository")).get("full_name", "")
        if repo_name:
            by_repo.setdefault(repo_name, []).append(alert)

    # Fetch SBOM versions for each repo
    repo_versions: dict[str, dict[str, str] | None] = {}
    for repo_name in by_repo:
        parts = repo_name.split("/")
        if len(parts) == 2:
            try:
                versions = await fetch_repo_sbom_versions(parts[0], parts[1], token)
            except Exception:
                versions = None
            repo_versions[repo_name] = versions
        else:
            repo_versions[repo_name] = None

    # Enrich alerts
    enriched: list[dict[str, Any]] = []
    for alert in alerts:
        repo_name = _as_record(alert.get("repository")).get("full_name", "")
        versions = repo_versions.get(repo_name)

        current_version = None
        if versions:
            dep = _as_record(alert.get("dependency"))
            pkg = _as_record(dep.get("package"))
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if ecosystem and name:
                key = _package_key(ecosystem, name)
                current_version = versions.get(key)

        enriched.append({**alert, "current_version": current_version})

    return enriched
