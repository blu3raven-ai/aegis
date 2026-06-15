"""Azure DevOps PR threads provider.

Azure uses a thread-of-comments model. We store the sticky marker as the first
comment of a thread; updates PATCH that comment in place.
"""
from __future__ import annotations

import base64
import logging

import httpx

from src.pr_feedback.git_pr_providers.base import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    TransientError,
)

logger = logging.getLogger(__name__)

_BASE = "https://dev.azure.com"
_API_VERSION = "7.1"


def _parse_repo(repo: str) -> tuple[str, str, str]:
    """Split 'org/project/repo' into its three parts. Raises ValueError otherwise."""
    parts = repo.split("/")
    if len(parts) != 3:
        raise ValueError(
            f"Azure DevOps repo must be 'org/project/repo'; got '{repo}'"
        )
    return parts[0], parts[1], parts[2]


class AzureDevOpsPrProvider:
    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def _client(self, token: str) -> httpx.Client:
        # Azure DevOps PAT auth: base64(":PAT") in Basic header
        encoded = base64.b64encode(f":{token}".encode()).decode()
        return httpx.Client(
            timeout=15.0,
            transport=self._transport,
            headers={
                "Authorization": f"Basic {encoded}",
                "Accept": "application/json",
                "User-Agent": "aegis-pr-feedback",
            },
        )

    def post_or_update_comment(
        self, *, repo: str, pr_number: int, body: str, marker: str, token: str,
    ) -> None:
        org, project, repo_name = _parse_repo(repo)
        threads_url = (
            f"{_BASE}/{org}/{project}/_apis/git/repositories/{repo_name}"
            f"/pullRequests/{pr_number}/threads"
        )

        with self._client(token) as client:
            resp = client.get(threads_url, params={"api-version": _API_VERSION})
            _raise_if_failed(resp)
            threads = (resp.json() or {}).get("value", [])

            matches = []
            for thread in threads:
                first = (thread.get("comments") or [{}])[0]
                content = first.get("content") or ""
                if marker in content:
                    matches.append((thread, first))

            if matches:
                matches.sort(key=lambda t: t[0].get("id", 0), reverse=True)
                thread, comment = matches[0]
                patch_url = f"{threads_url}/{thread['id']}/comments/{comment['id']}"
                resp = client.patch(
                    patch_url,
                    params={"api-version": _API_VERSION},
                    json={"content": body, "commentType": "text"},
                )
                _raise_if_failed(resp)

                for dup_thread, _dup_comment in matches[1:]:
                    del_url = f"{threads_url}/{dup_thread['id']}"
                    del_resp = client.patch(
                        del_url,
                        params={"api-version": _API_VERSION},
                        json={"status": "closed"},
                    )
                    if del_resp.status_code >= 500:
                        raise TransientError(f"close dup thread {dup_thread['id']}: {del_resp.status_code}")
            else:
                resp = client.post(
                    threads_url,
                    params={"api-version": _API_VERSION},
                    json={
                        "comments": [{
                            "parentCommentId": 0,
                            "content": body,
                            "commentType": "text",
                        }],
                        "status": "active",
                    },
                )
                _raise_if_failed(resp)


    async def resolve_pr_base_sha(
        self, *, repo: str, pr_number: int, token: str,
    ) -> str | None:
        """Return the last-merge target commit ID for an Azure DevOps pull request."""
        if not token:
            return None
        try:
            org, project, repo_name = _parse_repo(repo)
        except ValueError:
            return None
        try:
            encoded = base64.b64encode(f":{token}".encode()).decode()
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    f"{_BASE}/{org}/{project}/_apis/git/repositories/{repo_name}"
                    f"/pullrequests/{pr_number}",
                    params={"api-version": _API_VERSION},
                    headers={
                        "Authorization": f"Basic {encoded}",
                        "Accept": "application/json",
                        "User-Agent": "aegis-pr-feedback",
                    },
                )
                if r.status_code != 200:
                    logger.warning(
                        "resolve_pr_base_sha non-200 repo=%s pr=%d status=%d",
                        repo, pr_number, r.status_code,
                    )
                    return None
                return (r.json().get("lastMergeTargetCommit") or {}).get("commitId")
        except Exception:
            logger.exception("resolve_pr_base_sha failed repo=%s pr=%d", repo, pr_number)
            return None


def _raise_if_failed(resp: httpx.Response) -> None:
    if resp.status_code in (200, 201, 204):
        return
    if resp.status_code in (401, 403):
        raise AuthError(f"azure devops auth failed: {resp.status_code}")
    if resp.status_code == 404:
        raise NotFoundError(f"azure devops not found: {resp.text[:200]}")
    if resp.status_code == 429:
        ra = resp.headers.get("Retry-After", "30")
        retry_after = int(ra) if ra.isdigit() else 30
        raise RateLimitedError(retry_after_seconds=retry_after)
    if resp.status_code >= 500:
        raise TransientError(f"azure devops 5xx: {resp.status_code}")
    raise TransientError(f"azure devops unexpected: {resp.status_code} {resp.text[:200]}")
