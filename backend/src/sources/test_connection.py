from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from src.shared.url_guard import UnsafeURLError, assert_sendable_url

# Exceptions


class ConnectionTestError(Exception):
    """Raised when a connection test cannot be completed due to a logic error."""


# URL validation (SSRF prevention)


def _validate_instance_url(url: str) -> str:
    """Validate a user-supplied instance URL and return it with the hostname
    replaced by a pinned, validated IP address.

    Resolves the hostname once, rejects any address in private/internal ranges,
    then substitutes the resolved IP into the returned URL. Callers should pair
    this with _HostPinningTransport so TLS SNI still uses the original hostname.
    """
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ConnectionTestError(f"Invalid URL scheme: {parsed.scheme!r}. Use https://")

    hostname = parsed.hostname
    if not hostname:
        raise ConnectionTestError("Invalid URL: missing hostname")

    # Resolve once and validate every returned address.
    try:
        resolved_ip: str | None = None
        for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            addr = info[4][0]
            ip = ipaddress.ip_address(addr)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                raise ConnectionTestError(
                    f"URL resolves to a private/internal address ({addr}). "
                    "Only publicly routable instances are allowed."
                )
            if resolved_ip is None:
                resolved_ip = addr
    except socket.gaierror:
        raise ConnectionTestError(f"Cannot resolve hostname: {hostname}")

    if resolved_ip is None:
        raise ConnectionTestError(f"Cannot resolve hostname: {hostname}")

    # Replace hostname with the validated IP so the caller connects to the
    # address we checked, not whatever the next DNS lookup returns.
    ip_obj = ipaddress.ip_address(resolved_ip)
    ip_host = f"[{resolved_ip}]" if ip_obj.version == 6 else resolved_ip
    port_suffix = f":{parsed.port}" if parsed.port else ""
    pinned_netloc = f"{ip_host}{port_suffix}"
    pinned_url = urlunparse((
        parsed.scheme, pinned_netloc, parsed.path,
        parsed.params, parsed.query, parsed.fragment,
    ))
    return pinned_url.rstrip("/")


class _HostPinningTransport(httpx.AsyncHTTPTransport):
    """HTTP transport that preserves the original hostname for TLS SNI.

    When _validate_instance_url substitutes a validated IP for the hostname,
    this transport injects the original hostname as the TLS server name so
    certificate verification still works against the expected hostname.
    """

    def __init__(self, hostname: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        # httpcore reads extensions["sni_hostname"] for the TLS server name;
        # without this, connecting via IP would fail cert verification.
        request.extensions["sni_hostname"] = self._hostname.encode("ascii")
        return await super().handle_async_request(request)


# Result type


class ConnectionTestResult:
    """Holds the outcome of a single connection test."""

    def __init__(
        self,
        success: bool,
        message: str,
        discovered_count: int | None = None,
        discovered_items: list[str] | None = None,
    ) -> None:
        self.success = success
        self.message = message
        self.discovered_count = discovered_count
        self.discovered_items = discovered_items

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "discovered_count": self.discovered_count,
        }


# Dispatcher

async def test_connection(source_type: str, auth: dict) -> ConnectionTestResult:
    """Dispatch to the appropriate tester based on *source_type*."""
    testers = {
        "github": _test_github,
        "gitlab": _test_gitlab,
        "bitbucket": _test_bitbucket,
        "gitea": _test_gitea,
        "docker-hub": _test_docker_hub,
        "ghcr": _test_ghcr,
        "ecr": _test_ecr,
        "acr": _test_acr,
        "gcr": _test_gcr,
        "gitlab-registry": _test_gitlab_registry,
        "github-actions": _test_github_actions,
        "gitlab-ci": _test_gitlab_ci,
    }
    tester = testers.get(source_type)
    if tester is None:
        raise ConnectionTestError(f"Unknown source type: '{source_type}'")
    return await tester(auth)


# Helpers


async def _paginate_github(
    client: httpx.AsyncClient,
    url: str,
    headers: dict,
    params: dict,
    name_key: str = "name",
    max_items: int = 500,
    exclude_archived: bool = False,
    require_versions: bool = False,
) -> list[str]:
    """Paginate a GitHub list endpoint and collect item names.

    Args:
        require_versions: If True, skip items with version_count == 0.
            Useful for container packages where 0 versions means no pullable image.
    """
    items: list[str] = []
    page = 1
    per_page = params.get("per_page", 30)
    while len(items) < max_items:
        resp = await client.get(url, headers=headers, params={**params, "page": page})
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list) or len(data) == 0:
            break
        for item in data:
            if exclude_archived and (item.get("archived") or item.get("disabled")):
                continue
            if require_versions and item.get("version_count") == 0:
                continue
            name = item.get(name_key)
            if name:
                items.append(name)
        if len(data) < per_page:
            break
        page += 1
    return items[:max_items]


def _parse_github_total(response: httpx.Response) -> int:
    """Return total repo/package count from GitHub Link header pagination.

    If the Link header contains a ``rel="last"`` entry the page number is
    extracted and multiplied by the per-page default (30).  Falls back to the
    length of the JSON array in the response body when no Link header is
    present.
    """
    link_header = response.headers.get("Link", "")
    if link_header:
        for part in link_header.split(","):
            part = part.strip()
            if 'rel="last"' in part:
                # Extract URL from angle brackets
                url_part = part.split(";")[0].strip().lstrip("<").rstrip(">")
                for param in url_part.split("?")[-1].split("&"):
                    if param.startswith("page="):
                        try:
                            last_page = int(param.split("=", 1)[1])
                            # GitHub defaults to 30 per page
                            return last_page * 30
                        except ValueError:
                            pass
    # Fallback: count items in the current page
    try:
        data = response.json()
        if isinstance(data, list):
            return len(data)
    except Exception:
        pass
    return 0


# Individual testers


async def _test_github(auth: dict) -> ConnectionTestResult:
    """Test a GitHub personal-access-token connection."""
    token = auth.get("token")
    org = auth.get("orgOrOwner") or ""

    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # 1. Validate token and check scopes
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            user_resp.raise_for_status()
            username = user_resp.json().get("login", "")

            scopes_header = user_resp.headers.get("X-OAuth-Scopes", "")
            scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}

            missing = []
            if "repo" not in scopes:
                missing.append("repo")
            if org and "read:org" not in scopes:
                missing.append("read:org")
            if missing:
                return ConnectionTestResult(
                    success=False,
                    message=f"Token is missing required scopes: {', '.join(missing)}",
                )

            # 2. Collect repos — a specific org, or every repo the token can
            #    reach across all orgs + personal when no org is given.
            if org:
                url = f"https://api.github.com/orgs/{org}/repos"
                target = f"organisation '{org}'"
                params = {"per_page": 100}
            else:
                url = "https://api.github.com/user/repos"
                target = f"user '{username}'"
                params = {"per_page": 100, "affiliation": "owner,organization_member"}

            items = await _paginate_github(
                client,
                url,
                headers=headers,
                params=params,
                name_key="full_name",
                exclude_archived=True,
            )
            count = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            return ConnectionTestResult(success=False, message=f"Organisation '{org}' not found or not accessible")
        return ConnectionTestResult(success=False, message=f"GitHub API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to GitHub {target} — {count} repositories discovered",
        discovered_count=count,
        discovered_items=items,
    )


async def _test_gitlab(auth: dict) -> ConnectionTestResult:
    """Test a GitLab personal-access-token connection."""
    token = auth.get("token")
    raw_url = (auth.get("instanceUrl") or "https://gitlab.com").rstrip("/")
    try:
        instance_url = _validate_instance_url(raw_url)
    except ConnectionTestError as exc:
        return ConnectionTestResult(success=False, message=str(exc))
    original_hostname = urlparse(raw_url).hostname or ""
    group = auth.get("group") or auth.get("orgOrOwner")

    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    headers = {"PRIVATE-TOKEN": token}

    try:
        async with httpx.AsyncClient(timeout=15, transport=_HostPinningTransport(original_hostname)) as client:
            # 1. Validate token and check scopes
            token_resp = await client.get(
                f"{instance_url}/api/v4/personal_access_tokens/self",
                headers=headers,
            )
            token_resp.raise_for_status()

            token_data = token_resp.json()
            scopes: list[str] = token_data.get("scopes", [])

            missing = []
            if "read_api" not in scopes:
                missing.append("read_api")
            if "read_repository" not in scopes:
                missing.append("read_repository")
            if missing:
                return ConnectionTestResult(
                    success=False,
                    message=f"Token is missing required scopes: {', '.join(missing)}",
                )

            # 2. Collect projects
            items: list[str] = []
            page = 1
            while len(items) < 500:
                if group:
                    projects_resp = await client.get(
                        f"{instance_url}/api/v4/groups/{group}/projects",
                        headers=headers,
                        params={"per_page": 100, "page": page},
                    )
                else:
                    projects_resp = await client.get(
                        f"{instance_url}/api/v4/projects",
                        headers=headers,
                        params={"per_page": 100, "page": page, "owned": "true"},
                    )
                projects_resp.raise_for_status()
                data = projects_resp.json()
                if not isinstance(data, list) or len(data) == 0:
                    break
                for p in data:
                    name = p.get("path_with_namespace") or p.get("name")
                    if name:
                        items.append(name)
                if len(data) < 100:
                    break
                page += 1
            count: int | None = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            target = f"group '{group}'" if group else "projects"
            return ConnectionTestResult(success=False, message=f"GitLab {target} not found or not accessible")
        return ConnectionTestResult(success=False, message=f"GitLab API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    count_label = f"{count} projects discovered" if count is not None else "projects accessible"
    target_label = f"group '{group}'" if group else "instance"
    return ConnectionTestResult(
        success=True,
        message=f"Connected to GitLab {target_label} — {count_label}",
        discovered_count=count,
        discovered_items=items,
    )


async def _test_docker_hub(auth: dict) -> ConnectionTestResult:
    """Test a Docker Hub username/token connection."""
    username = auth.get("username")
    token = auth.get("token")

    if not username:
        return ConnectionTestResult(success=False, message="Missing required field: username")
    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # 1. Authenticate
            login_resp = await client.post(
                "https://hub.docker.com/v2/users/login",
                json={"username": username, "password": token},
            )
            login_resp.raise_for_status()
            jwt = login_resp.json().get("token")
            if not jwt:
                return ConnectionTestResult(success=False, message="Login succeeded but no token was returned")

            # 2. Collect repositories
            items: list[str] = []
            page_url: str | None = f"https://hub.docker.com/v2/repositories/{username}/"
            while page_url and len(items) < 500:
                repos_resp = await client.get(
                    page_url,
                    headers={"Authorization": f"JWT {jwt}"},
                    params={"page_size": 100} if page_url.startswith("https://hub.docker.com") else {},
                )
                repos_resp.raise_for_status()
                data = repos_resp.json()
                for repo in data.get("results", []):
                    name = repo.get("name")
                    if name:
                        items.append(f"{username}/{name}")
                next_url = data.get("next")
                page_url = next_url if isinstance(next_url, str) and next_url.startswith("https://hub.docker.com/") else None
            count: int | None = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid username or token")
        if status == 404:
            return ConnectionTestResult(success=False, message=f"User '{username}' not found on Docker Hub")
        return ConnectionTestResult(success=False, message=f"Docker Hub API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    count_label = f"{count} repositories discovered" if count is not None else "repositories accessible"
    return ConnectionTestResult(
        success=True,
        message=f"Connected to Docker Hub as '{username}' — {count_label}",
        discovered_count=count,
        discovered_items=items,
    )


async def _test_ghcr(auth: dict) -> ConnectionTestResult:
    """Test a GitHub Container Registry connection."""
    token = auth.get("token")
    org = auth.get("orgOrOwner") or ""

    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            # 1. Validate token and check scopes
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            user_resp.raise_for_status()
            username = user_resp.json().get("login", "")

            scopes_header = user_resp.headers.get("X-OAuth-Scopes", "")
            scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}

            if "read:packages" not in scopes:
                return ConnectionTestResult(
                    success=False,
                    message="Token is missing required scope: read:packages",
                )

            # 2. Collect container packages — org or user
            if org:
                url = f"https://api.github.com/orgs/{org}/packages"
                target = f"organisation '{org}'"
            else:
                url = f"https://api.github.com/user/packages"
                target = f"user '{username}'"

            all_packages = await _paginate_github(
                client,
                url,
                headers=headers,
                params={"package_type": "container", "per_page": 100},
                require_versions=True,
            )

            # 3. Filter and resolve tags concurrently (max 10 in parallel)
            #    - Skips packages with no versions or no tags
            #    - Stores "{name}:{tag}" using "latest" if available, else the most recent tag
            semaphore = asyncio.Semaphore(10)

            async def resolve_package(pkg_name: str) -> str | None:
                async with semaphore:
                    try:
                        encoded = pkg_name.replace("/", "%2F")
                        versions_url = f"https://api.github.com/orgs/{org}/packages/container/{encoded}/versions" if org else f"https://api.github.com/user/packages/container/{encoded}/versions"
                        v_resp = await client.get(versions_url, headers=headers, params={"per_page": 5})
                        if v_resp.status_code != 200:
                            return None
                        versions = v_resp.json()
                        if not versions:
                            return None
                        all_tags: list[str] = []
                        for v in versions:
                            all_tags.extend(v.get("metadata", {}).get("container", {}).get("tags", []))
                        if not all_tags:
                            return None
                        tag = "latest" if "latest" in all_tags else all_tags[0]
                        return f"{pkg_name}:{tag}"
                    except Exception:
                        return pkg_name

            results = await asyncio.gather(*(resolve_package(p) for p in all_packages))
            items = [r for r in results if r is not None]
            skipped = len(all_packages) - len(items)
            count = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            return ConnectionTestResult(success=False, message=f"Organisation '{org}' not found or not accessible")
        return ConnectionTestResult(success=False, message=f"GitHub API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to GHCR for {target} — {count} scannable container packages discovered" + (f" ({skipped} skipped: no tags or empty)" if skipped else ""),
        discovered_count=count,
        discovered_items=items,
    )


async def _test_github_actions(auth: dict) -> ConnectionTestResult:
    """Test a GitHub Actions connection."""
    token = auth.get("token")
    org = auth.get("orgOrOwner") or ""

    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            # 1. Validate token and check scopes
            user_resp = await client.get("https://api.github.com/user", headers=headers)
            user_resp.raise_for_status()
            username = user_resp.json().get("login", "")

            scopes_header = user_resp.headers.get("X-OAuth-Scopes", "")
            scopes = {s.strip() for s in scopes_header.split(",") if s.strip()}

            missing = []
            if "repo" not in scopes:
                missing.append("repo")
            if org and "read:org" not in scopes:
                missing.append("read:org")
            if missing:
                return ConnectionTestResult(
                    success=False,
                    message=f"Token is missing required scopes: {', '.join(missing)}",
                )

            # 2. Collect repos then filter to those with workflows
            if org:
                url = f"https://api.github.com/orgs/{org}/repos"
                target = f"organisation '{org}'"
            else:
                url = "https://api.github.com/user/repos"
                target = f"user '{username}'"

            all_repos = await _paginate_github(
                client,
                url,
                headers=headers,
                params={"per_page": 100},
                name_key="full_name",
                exclude_archived=True,
            )

            # Check each repo for workflows (batched, max 10 concurrent)
            semaphore = asyncio.Semaphore(10)

            async def has_workflows(repo_full_name: str) -> str | None:
                async with semaphore:
                    try:
                        resp = await client.get(
                            f"https://api.github.com/repos/{repo_full_name}/actions/workflows",
                            headers=headers,
                            params={"per_page": 1},
                        )
                        if resp.status_code == 200:
                            data = resp.json()
                            if data.get("total_count", 0) > 0:
                                return repo_full_name
                    except httpx.HTTPError:
                        pass
                    return None

            results = await asyncio.gather(*(has_workflows(r) for r in all_repos))
            items = [r for r in results if r is not None]
            count = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            return ConnectionTestResult(success=False, message=f"Organisation '{org}' not found or not accessible")
        return ConnectionTestResult(success=False, message=f"GitHub API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to GitHub Actions for {target} — {count} pipelines discovered",
        discovered_count=count,
        discovered_items=items,
    )


async def _test_gitlab_ci(auth: dict) -> ConnectionTestResult:
    """Test a GitLab CI connection."""
    token = auth.get("token")
    raw_url = (auth.get("instanceUrl") or "https://gitlab.com").rstrip("/")
    try:
        instance_url = _validate_instance_url(raw_url)
    except ConnectionTestError as exc:
        return ConnectionTestResult(success=False, message=str(exc))
    original_hostname = urlparse(raw_url).hostname or ""
    group = auth.get("group") or auth.get("orgOrOwner")

    if not token:
        return ConnectionTestResult(success=False, message="Missing required field: token")

    headers = {"PRIVATE-TOKEN": token}

    try:
        async with httpx.AsyncClient(timeout=15, transport=_HostPinningTransport(original_hostname)) as client:
            # 1. Validate token and check scopes
            token_resp = await client.get(
                f"{instance_url}/api/v4/personal_access_tokens/self",
                headers=headers,
            )
            token_resp.raise_for_status()

            token_data = token_resp.json()
            scopes: list[str] = token_data.get("scopes", [])

            if "read_api" not in scopes:
                return ConnectionTestResult(
                    success=False,
                    message="Token is missing required scope: read_api",
                )

            # 2. Collect projects
            items: list[str] = []
            page = 1
            while len(items) < 500:
                if group:
                    projects_resp = await client.get(
                        f"{instance_url}/api/v4/groups/{group}/projects",
                        headers=headers,
                        params={"per_page": 100, "page": page},
                    )
                else:
                    projects_resp = await client.get(
                        f"{instance_url}/api/v4/projects",
                        headers=headers,
                        params={"per_page": 100, "page": page, "owned": "true"},
                    )
                projects_resp.raise_for_status()
                data = projects_resp.json()
                if not isinstance(data, list) or len(data) == 0:
                    break
                for p in data:
                    name = p.get("path_with_namespace") or p.get("name")
                    if name:
                        items.append(name)
                if len(data) < 100:
                    break
                page += 1
            count: int | None = len(items)

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            target = f"group '{group}'" if group else "projects"
            return ConnectionTestResult(success=False, message=f"GitLab {target} not found or not accessible")
        return ConnectionTestResult(success=False, message=f"GitLab API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    count_label = f"{count} pipelines discovered" if count is not None else "pipelines accessible"
    target_label = f"group '{group}'" if group else "instance"
    return ConnectionTestResult(
        success=True,
        message=f"Connected to GitLab CI {target_label} — {count_label}",
        discovered_count=count,
        discovered_items=items,
    )


# Bitbucket


async def _test_bitbucket(auth: dict) -> ConnectionTestResult:
    """Test a Bitbucket Cloud app-password connection."""
    username = auth.get("username") or ""
    token = auth.get("token")
    workspace = auth.get("orgOrOwner") or ""
    if not token:
        return ConnectionTestResult(success=False, message="App password is required")
    if not workspace:
        return ConnectionTestResult(success=False, message="Workspace slug is required")

    headers = {"Accept": "application/json"}
    basic_auth = (username or workspace, token)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Verify access
            resp = await client.get(
                f"https://api.bitbucket.org/2.0/repositories/{workspace}",
                headers=headers,
                auth=basic_auth,
                params={"pagelen": 100, "fields": "values.full_name,next,size"},
            )
            resp.raise_for_status()
            data = resp.json()

            items: list[str] = []
            total = data.get("size", 0)
            for repo in data.get("values", []):
                full_name = repo.get("full_name", "")
                if full_name:
                    items.append(full_name)

            # Paginate
            next_url = data.get("next")
            while next_url and len(items) < 500:
                resp = await client.get(next_url, headers=headers, auth=basic_auth)
                resp.raise_for_status()
                data = resp.json()
                for repo in data.get("values", []):
                    full_name = repo.get("full_name", "")
                    if full_name:
                        items.append(full_name)
                next_url = data.get("next")

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid app password")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            return ConnectionTestResult(success=False, message=f"Workspace '{workspace}' not found")
        return ConnectionTestResult(success=False, message=f"Bitbucket API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to Bitbucket workspace '{workspace}' — {total} repositories discovered",
        discovered_count=total,
        discovered_items=items[:500],
    )


# Gitea


async def _test_gitea(auth: dict) -> ConnectionTestResult:
    """Test a Gitea/Forgejo instance connection."""
    token = auth.get("token")
    org = auth.get("orgOrOwner") or ""
    instance_url = (auth.get("instanceUrl") or "").rstrip("/")
    if not token:
        return ConnectionTestResult(success=False, message="Access token is required")
    if not instance_url:
        return ConnectionTestResult(success=False, message="Instance URL is required")

    base_url = _validate_instance_url(instance_url)
    original_hostname = urlparse(instance_url).hostname or ""
    headers = {"Authorization": f"token {token}", "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30, transport=_HostPinningTransport(original_hostname)) as client:
            # Verify token
            resp = await client.get(f"{base_url}/api/v1/user", headers=headers)
            resp.raise_for_status()

            # List repos
            items: list[str] = []
            page = 1
            while len(items) < 500:
                if org:
                    url = f"{base_url}/api/v1/orgs/{org}/repos"
                else:
                    url = f"{base_url}/api/v1/user/repos"
                resp = await client.get(url, headers=headers, params={"page": page, "limit": 50})
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list) or len(data) == 0:
                    break
                for repo in data:
                    full_name = repo.get("full_name") or repo.get("name", "")
                    if full_name:
                        items.append(full_name)
                if len(data) < 50:
                    break
                page += 1

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: insufficient permissions")
        if status == 404:
            target = f"organization '{org}'" if org else "user"
            return ConnectionTestResult(success=False, message=f"Gitea {target} not found")
        return ConnectionTestResult(success=False, message=f"Gitea API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    target_label = f"organization '{org}'" if org else "user account"
    return ConnectionTestResult(
        success=True,
        message=f"Connected to Gitea {target_label} — {len(items)} repositories discovered",
        discovered_count=len(items),
        discovered_items=items[:500],
    )


# AWS ECR


async def _test_ecr(auth: dict) -> ConnectionTestResult:
    """Test an AWS ECR connection using registry URL + access token.

    For ECR, the user provides the registry URL (e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com)
    and a pre-generated auth token (from `aws ecr get-login-password`).
    """
    registry_url = (auth.get("instanceUrl") or "").rstrip("/")
    token = auth.get("token")
    if not token:
        return ConnectionTestResult(success=False, message="ECR auth token is required (from aws ecr get-login-password)")
    if not registry_url:
        return ConnectionTestResult(success=False, message="Registry URL is required (e.g. 123456789.dkr.ecr.us-east-1.amazonaws.com)")

    try:
        assert_sendable_url(f"https://{registry_url}")
    except UnsafeURLError as exc:
        return ConnectionTestResult(success=False, message=f"Registry URL not permitted: {exc}")

    import base64
    b64_auth = base64.b64encode(f"AWS:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}", "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://{registry_url}/v2/_catalog", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            repos = data.get("repositories", [])

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: ECR token may be expired (tokens last 12 hours)")
        return ConnectionTestResult(success=False, message=f"ECR API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to ECR — {len(repos)} repositories discovered",
        discovered_count=len(repos),
        discovered_items=repos[:500],
    )


# Azure ACR


async def _test_acr(auth: dict) -> ConnectionTestResult:
    """Test an Azure Container Registry connection."""
    registry_url = (auth.get("instanceUrl") or "").rstrip("/")
    token = auth.get("token")
    if not token:
        return ConnectionTestResult(success=False, message="ACR admin password or token is required")
    if not registry_url:
        return ConnectionTestResult(success=False, message="Registry URL is required (e.g. myregistry.azurecr.io)")

    try:
        assert_sendable_url(f"https://{registry_url}")
    except UnsafeURLError as exc:
        return ConnectionTestResult(success=False, message=f"Registry URL not permitted: {exc}")

    username = auth.get("username") or registry_url.split(".")[0]

    import base64
    b64_auth = base64.b64encode(f"{username}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://{registry_url}/v2/_catalog", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            repos = data.get("repositories", [])

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: check username and password/token")
        return ConnectionTestResult(success=False, message=f"ACR API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to ACR — {len(repos)} repositories discovered",
        discovered_count=len(repos),
        discovered_items=repos[:500],
    )


# Google GCR / Artifact Registry


async def _test_gcr(auth: dict) -> ConnectionTestResult:
    """Test a Google Container Registry or Artifact Registry connection."""
    registry_url = (auth.get("instanceUrl") or "gcr.io").rstrip("/")
    token = auth.get("token")
    org = auth.get("orgOrOwner") or ""
    if not token:
        return ConnectionTestResult(success=False, message="Service account JSON key or access token is required")

    try:
        assert_sendable_url(f"https://{registry_url}")
    except UnsafeURLError as exc:
        return ConnectionTestResult(success=False, message=f"Registry URL not permitted: {exc}")

    import base64
    b64_auth = base64.b64encode(f"_json_key:{token}".encode()).decode() if token.strip().startswith("{") \
        else base64.b64encode(f"oauth2accesstoken:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {b64_auth}"}

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(f"https://{registry_url}/v2/_catalog", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            repos = data.get("repositories", [])
            if org:
                repos = [r for r in repos if r.startswith(f"{org}/") or r == org]

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: check service account key or access token")
        return ConnectionTestResult(success=False, message=f"GCR API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    return ConnectionTestResult(
        success=True,
        message=f"Connected to GCR — {len(repos)} repositories discovered",
        discovered_count=len(repos),
        discovered_items=repos[:500],
    )


# GitLab Container Registry


async def _test_gitlab_registry(auth: dict) -> ConnectionTestResult:
    """Test a GitLab Container Registry connection."""
    token = auth.get("token")
    instance_url = (auth.get("instanceUrl") or "https://gitlab.com").rstrip("/")
    group = auth.get("groupOrProject") or auth.get("orgOrOwner") or ""
    if not token:
        return ConnectionTestResult(success=False, message="Access token is required")
    if not group:
        return ConnectionTestResult(success=False, message="Group or project path is required")

    base_url = _validate_instance_url(instance_url)
    original_hostname = urlparse(instance_url).hostname or ""
    headers = {"PRIVATE-TOKEN": token, "Accept": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=30, transport=_HostPinningTransport(original_hostname)) as client:
            items: list[str] = []
            page = 1

            from urllib.parse import quote
            encoded_group = quote(group, safe="")
            url = f"{base_url}/api/v4/groups/{encoded_group}/registry/repositories"

            while len(items) < 500:
                resp = await client.get(url, headers=headers, params={"page": page, "per_page": 100})
                resp.raise_for_status()
                data = resp.json()
                if not isinstance(data, list) or len(data) == 0:
                    break
                for repo in data:
                    path = repo.get("path") or repo.get("name", "")
                    if path:
                        items.append(path)
                if len(data) < 100:
                    break
                page += 1

    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code
        if status == 401:
            return ConnectionTestResult(success=False, message="Authentication failed: invalid or expired token")
        if status == 403:
            return ConnectionTestResult(success=False, message="Access forbidden: token needs read_registry scope")
        if status == 404:
            target = f"group '{group}'" if group else "registry"
            return ConnectionTestResult(success=False, message=f"GitLab {target} not found")
        return ConnectionTestResult(success=False, message=f"GitLab Registry API error: HTTP {status}")
    except httpx.HTTPError as exc:
        return ConnectionTestResult(success=False, message=f"Network error: {exc}")

    target_label = f"group '{group}'" if group else "instance"
    return ConnectionTestResult(
        success=True,
        message=f"Connected to GitLab Registry {target_label} — {len(items)} images discovered",
        discovered_count=len(items),
        discovered_items=items[:500],
    )
