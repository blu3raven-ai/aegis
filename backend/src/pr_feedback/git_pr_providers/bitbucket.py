"""Bitbucket Cloud PR comment provider."""
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

_BASE = "https://api.bitbucket.org/2.0"
_MAX_PAGES = 5  # cap pagination to avoid runaway on large PRs


class BitbucketPrProvider:
    def __init__(self, *, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def _client(self, token: str) -> httpx.Client:
        return httpx.Client(
            timeout=15.0,
            transport=self._transport,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": "aegis-pr-feedback",
            },
        )

    def post_or_update_comment(
        self, *, repo: str, pr_number: int, body: str, marker: str, token: str,
    ) -> None:
        list_url = f"{_BASE}/repositories/{repo}/pullrequests/{pr_number}/comments"

        with self._client(token) as client:
            with_marker = list(self._iter_comments_with_marker(client, list_url, marker))

            if with_marker:
                with_marker.sort(key=lambda c: c.get("id", 0), reverse=True)
                keeper = with_marker[0]
                update_url = f"{list_url}/{keeper['id']}"
                resp = client.put(update_url, json={"content": {"raw": body}})
                _raise_if_failed(resp)

                for dup in with_marker[1:]:
                    del_resp = client.delete(f"{list_url}/{dup['id']}")
                    if del_resp.status_code >= 500:
                        raise TransientError(f"delete dup {dup['id']}: {del_resp.status_code}")
            else:
                resp = client.post(list_url, json={"content": {"raw": body}})
                _raise_if_failed(resp)

    def _iter_comments_with_marker(self, client: httpx.Client, url: str, marker: str):
        first = True
        for _ in range(_MAX_PAGES):
            # Only add pagelen on the first request; subsequent pages use the
            # `next` URL verbatim (which already carries its own pagination params).
            resp = client.get(url, params={"pagelen": 100} if first else None)
            first = False
            _raise_if_failed(resp)
            data = resp.json()
            for c in data.get("values", []):
                raw = (c.get("content") or {}).get("raw") or ""
                if marker in raw:
                    yield c
            url = data.get("next")
            if not url:
                return


    async def resolve_pr_base_sha(
        self, *, repo: str, pr_number: int, token: str,
    ) -> str | None:
        """Return the destination commit hash for a Bitbucket pull request."""
        if not token:
            return None
        try:
            async with httpx.AsyncClient(timeout=10.0) as c:
                r = await c.get(
                    f"{_BASE}/repositories/{repo}/pullrequests/{pr_number}",
                    headers={
                        "Authorization": f"Bearer {token}",
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
                return ((r.json().get("destination") or {}).get("commit") or {}).get("hash")
        except Exception:
            logger.exception("resolve_pr_base_sha failed repo=%s pr=%d", repo, pr_number)
            return None


def _raise_if_failed(resp: httpx.Response) -> None:
    if resp.status_code in (200, 201, 204):
        return
    if resp.status_code in (401, 403):
        raise AuthError(f"bitbucket auth failed: {resp.status_code}")
    if resp.status_code == 404:
        raise NotFoundError(f"bitbucket not found: {resp.text[:200]}")
    if resp.status_code == 429:
        ra = resp.headers.get("Retry-After", "30")
        retry_after = int(ra) if ra.isdigit() else 30
        raise RateLimitedError(retry_after_seconds=retry_after)
    if resp.status_code >= 500:
        raise TransientError(f"bitbucket 5xx: {resp.status_code}")
    raise TransientError(f"bitbucket unexpected: {resp.status_code} {resp.text[:200]}")
