"""GitHub PR comment provider."""
from __future__ import annotations

import logging

import httpx

from src.pr_feedback.git_pr_providers.base import (
    AuthError,
    NotFoundError,
    RateLimitedError,
    TransientError,
)

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_USER_AGENT = "aegis-pr-feedback"


class GitHubPrProvider:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=15.0,
            transport=self._transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": _USER_AGENT,
            },
        )

    def post_or_update_comment(
        self,
        *,
        repo: str,
        pr_number: int,
        body: str,
        marker: str,
        token: str,
    ) -> None:
        with self._client(token) as client:
            list_url = f"{_API}/repos/{repo}/issues/{pr_number}/comments"
            resp = client.get(list_url, params={"per_page": 100})
            _raise_if_failed(resp)
            existing = resp.json() if isinstance(resp.json(), list) else []
            with_marker = [c for c in existing if marker in (c.get("body") or "")]

            if with_marker:
                with_marker.sort(key=lambda c: c.get("id", 0), reverse=True)
                keeper = with_marker[0]
                patch_resp = client.patch(
                    f"{_API}/repos/{repo}/issues/comments/{keeper['id']}",
                    json={"body": body},
                )
                _raise_if_failed(patch_resp)

                for duplicate in with_marker[1:]:
                    del_resp = client.delete(
                        f"{_API}/repos/{repo}/issues/comments/{duplicate['id']}"
                    )
                    if del_resp.status_code >= 500:
                        raise TransientError(f"delete dup {duplicate['id']}: {del_resp.status_code}")
            else:
                post_resp = client.post(list_url, json={"body": body})
                _raise_if_failed(post_resp)


    async def resolve_pr_base_sha(
        self, *, repo: str, pr_number: int, token: str,
    ) -> str | None:
        """Return the base-commit SHA for a GitHub pull request."""
        if not token:
            return None
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    f"{_API}/repos/{repo}/pulls/{pr_number}",
                    headers={
                        "Authorization": f"token {token}",
                        "Accept": "application/vnd.github+json",
                        "User-Agent": _USER_AGENT,
                    },
                )
                if r.status_code != 200:
                    logger.warning(
                        "resolve_pr_base_sha non-200 repo=%s pr=%d status=%d",
                        repo, pr_number, r.status_code,
                    )
                    return None
                return (r.json().get("base") or {}).get("sha")
        except Exception:
            logger.exception("resolve_pr_base_sha failed repo=%s pr=%d", repo, pr_number)
            return None


def _raise_if_failed(resp: httpx.Response) -> None:
    if resp.status_code in (200, 201, 204):
        return
    if resp.status_code == 429 or (resp.status_code == 403 and "rate limit" in resp.text.lower()):
        retry_after = None
        try:
            retry_after = int(resp.headers.get("Retry-After", "30"))
        except (TypeError, ValueError):
            retry_after = 30
        raise RateLimitedError(retry_after_seconds=retry_after)
    if resp.status_code in (401, 403):
        raise AuthError(f"github auth failed: {resp.status_code} {resp.text[:200]}")
    if resp.status_code == 404:
        raise NotFoundError(f"github resource not found: {resp.text[:200]}")
    if resp.status_code >= 500:
        raise TransientError(f"github 5xx: {resp.status_code} {resp.text[:200]}")
    raise TransientError(f"github unexpected: {resp.status_code} {resp.text[:200]}")
