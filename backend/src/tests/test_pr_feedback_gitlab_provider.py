"""GitLab MR notes provider."""
from __future__ import annotations

import json
from urllib.parse import quote

import httpx
import pytest

from src.pr_feedback.git_pr_providers.base import (
    AuthError,
    RateLimitedError,
)
from src.pr_feedback.git_pr_providers.gitlab import GitLabPrProvider
from src.pr_feedback.render import MARKER_PREFIX


def _resp(status: int, body=None) -> httpx.Response:
    return httpx.Response(status_code=status, json=body if body is not None else {})


def test_creates_new_note_when_no_existing_marker():
    posted: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, [{"id": 100, "body": "lgtm"}])
        if req.method == "POST":
            posted.append(json.loads(req.content.decode()))
            return _resp(201, {"id": 999})
        return _resp(500)

    provider = GitLabPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=s1 -->\nbody",
        marker=MARKER_PREFIX, token="glpat-fake",
    )
    assert len(posted) == 1
    assert "body" in posted[0]


def test_patches_existing_note_when_marker_present():
    patched: list[tuple[int, dict]] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, [
                {"id": 500, "body": f"{MARKER_PREFIX}scan=old -->\nstale"},
                {"id": 501, "body": "unrelated"},
            ])
        if req.method == "PUT":
            note_id = int(req.url.path.rsplit("/", 1)[-1])
            patched.append((note_id, json.loads(req.content.decode())))
            return _resp(200, {"id": note_id})
        return _resp(500)

    provider = GitLabPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=new -->\nfresh",
        marker=MARKER_PREFIX, token="glpat-fake",
    )
    assert patched == [(500, {"body": f"{MARKER_PREFIX}scan=new -->\nfresh"})]


def test_unauthorized_raises_auth_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return _resp(401)

    provider = GitLabPrProvider(transport=httpx.MockTransport(handler))
    with pytest.raises(AuthError):
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=42,
            body="x", marker=MARKER_PREFIX, token="bad",
        )


def test_rate_limited_raises_rate_limit_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=429, headers={"Retry-After": "20"})

    provider = GitLabPrProvider(transport=httpx.MockTransport(handler))
    with pytest.raises(RateLimitedError) as exc:
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=42,
            body="x", marker=MARKER_PREFIX, token="ok",
        )
    assert exc.value.retry_after_seconds == 20


def test_url_encodes_project_path():
    seen: list[bytes] = []

    def handler(req: httpx.Request) -> httpx.Response:
        # Use raw_path to get the percent-encoded form before httpx decodes it
        seen.append(req.url.raw_path)
        return _resp(200, [])

    provider = GitLabPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/sub/project", pr_number=42,
        body="x", marker=MARKER_PREFIX, token="t",
    )
    # GitLab requires URL-encoded namespace/project path
    encoded = quote("acme-org/sub/project", safe="").encode()
    assert encoded in seen[0]
