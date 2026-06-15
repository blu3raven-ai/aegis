"""GitLab MR notes provider."""
from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from src.pr_feedback.git_pr_providers.base import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    TransientError,
)

logger = logging.getLogger(__name__)

_DEFAULT_BASE = "https://gitlab.com/api/v4"


class GitLabPrProvider:
    def __init__(
        self,
        *,
        base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")
        self._transport = transport

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=15.0,
            transport=self._transport,
            headers={
                "PRIVATE-TOKEN": token,
                "Accept": "application/json",
                "User-Agent": "aegis-pr-feedback",
            },
        )

    def post_or_update_comment(
        self, *, repo: str, pr_number: int, body: str, marker: str, token: str,
    ) -> None:
        encoded = quote(repo, safe="")
        with self._client(token) as client:
            list_url = f"{self._base}/projects/{encoded}/merge_requests/{pr_number}/notes"
            resp = client.get(list_url, params={"per_page": 100, "sort": "desc"})
            _raise_if_failed(resp)
            existing = resp.json() if isinstance(resp.json(), list) else []
            with_marker = [n for n in existing if marker in (n.get("body") or "")]

            if with_marker:
                with_marker.sort(key=lambda n: n.get("id", 0), reverse=True)
                keeper = with_marker[0]
                patch_resp = client.put(
                    f"{self._base}/projects/{encoded}/merge_requests/{pr_number}/notes/{keeper['id']}",
                    json={"body": body},
                )
                _raise_if_failed(patch_resp)

                for duplicate in with_marker[1:]:
                    del_resp = client.delete(
                        f"{self._base}/projects/{encoded}/merge_requests/{pr_number}/notes/{duplicate['id']}"
                    )
                    if del_resp.status_code >= 500:
                        raise TransientError(f"delete dup {duplicate['id']}: {del_resp.status_code}")
            else:
                post_resp = client.post(list_url, json={"body": body})
                _raise_if_failed(post_resp)


    async def resolve_pr_base_sha(
        self, *, repo: str, pr_number: int, token: str,
    ) -> str | None:
        """Return the base-commit SHA for a GitLab merge request."""
        if not token:
            return None
        try:
            encoded = quote(repo, safe="")
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    f"{self._base}/projects/{encoded}/merge_requests/{pr_number}",
                    headers={
                        "PRIVATE-TOKEN": token,
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
                return (r.json().get("diff_refs") or {}).get("base_sha")
        except Exception:
            logger.exception("resolve_pr_base_sha failed repo=%s pr=%d", repo, pr_number)
            return None


def _raise_if_failed(resp: httpx.Response) -> None:
    if resp.status_code in (200, 201, 204):
        return
    if resp.status_code in (401, 403):
        raise AuthError(f"gitlab auth failed: {resp.status_code}")
    if resp.status_code == 404:
        raise NotFoundError(f"gitlab not found: {resp.text[:200]}")
    if resp.status_code == 429:
        ra = resp.headers.get("Retry-After", "30")
        retry_after = int(ra) if ra.isdigit() else 30
        raise RateLimitedError(retry_after_seconds=retry_after)
    if resp.status_code >= 500:
        raise TransientError(f"gitlab 5xx: {resp.status_code}")
    raise TransientError(f"gitlab unexpected: {resp.status_code} {resp.text[:200]}")
