"""Tests for the GitHub PR provider (sticky comment post/patch)."""
from __future__ import annotations

import json

import httpx
import pytest

from src.pr_feedback.git_pr_providers.github import GitHubPrProvider
from src.pr_feedback.render import MARKER_PREFIX


def _resp(status: int, body=None) -> httpx.Response:
    return httpx.Response(status_code=status, json=body if body is not None else {})


def test_creates_new_comment_when_no_existing_marker():
    posted: list[dict] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return _resp(200, [
                {"id": 100, "body": "lgtm"},
                {"id": 101, "body": "other comment"},
            ])
        if request.method == "POST":
            posted.append(json.loads(request.content.decode()))
            return _resp(201, {"id": 999})
        return _resp(500)

    provider = GitHubPrProvider(transport=httpx.MockTransport(transport_handler))
    provider.post_or_update_comment(
        repo="acme-org/api",
        pr_number=247,
        body=f"{MARKER_PREFIX}scan=scan-1 -->\nbody",
        marker=f"{MARKER_PREFIX}scan=scan-1 -->",
        token="ghp_fake",
    )
    assert len(posted) == 1
    assert "body" in posted[0]


def test_patches_existing_comment_when_marker_present():
    patched: list[tuple[int, dict]] = []

    def transport_handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return _resp(200, [
                {"id": 500, "body": f"{MARKER_PREFIX}scan=older -->\nstale"},
                {"id": 501, "body": "unrelated"},
            ])
        if request.method == "PATCH":
            comment_id = int(request.url.path.rsplit("/", 1)[-1])
            patched.append((comment_id, json.loads(request.content.decode())))
            return _resp(200, {"id": comment_id})
        return _resp(500)

    provider = GitHubPrProvider(transport=httpx.MockTransport(transport_handler))
    provider.post_or_update_comment(
        repo="acme-org/api",
        pr_number=247,
        body=f"{MARKER_PREFIX}scan=scan-2 -->\nfresh body",
        marker=MARKER_PREFIX,
        token="ghp_fake",
    )
    assert patched == [(500, {"body": f"{MARKER_PREFIX}scan=scan-2 -->\nfresh body"})]


def test_unauthorized_raises_auth_error():
    def transport_handler(request: httpx.Request) -> httpx.Response:
        return _resp(401, {"message": "Bad credentials"})

    provider = GitHubPrProvider(transport=httpx.MockTransport(transport_handler))
    from src.pr_feedback.git_pr_providers.base import AuthError
    with pytest.raises(AuthError):
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=247,
            body="x", marker=MARKER_PREFIX, token="bad",
        )


def test_rate_limited_raises_rate_limit_error():
    def transport_handler(request: httpx.Request) -> httpx.Response:
        return _resp(429, {"message": "rate limit"})

    provider = GitHubPrProvider(transport=httpx.MockTransport(transport_handler))
    from src.pr_feedback.git_pr_providers.base import RateLimitedError
    with pytest.raises(RateLimitedError):
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=247,
            body="x", marker=MARKER_PREFIX, token="ok",
        )
