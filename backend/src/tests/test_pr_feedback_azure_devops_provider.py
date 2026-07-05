"""Azure DevOps PR threads provider."""
from __future__ import annotations

import json

import httpx
import pytest

from src.pr_feedback.git_pr_providers.base import AuthError
from src.pr_feedback.git_pr_providers.azure_devops import AzureDevOpsPrProvider
from src.pr_feedback.render import MARKER_PREFIX


def _resp(status: int, body=None) -> httpx.Response:
    return httpx.Response(status_code=status, json=body if body is not None else {})


def test_creates_new_thread_when_no_existing_marker():
    posted: list[dict] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, {"value": []})
        if req.method == "POST":
            posted.append(json.loads(req.content.decode()))
            return _resp(201, {"id": 999})
        return _resp(500)

    provider = AzureDevOpsPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/proj/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=s1 -->\nbody",
        marker=MARKER_PREFIX, token="azpat",
    )
    assert len(posted) == 1
    assert posted[0]["comments"][0]["content"].startswith(MARKER_PREFIX)
    assert posted[0]["status"] == "active"


def test_patches_existing_thread_comment_when_marker_present():
    patched = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, {"value": [
                {
                    "id": 500,
                    "comments": [
                        {"id": 1, "content": f"{MARKER_PREFIX}scan=old -->\nstale"},
                    ],
                },
                {
                    "id": 501,
                    "comments": [
                        {"id": 1, "content": "unrelated"},
                    ],
                },
            ]})
        if req.method == "PATCH":
            patched.append((req.url.path, json.loads(req.content.decode())))
            return _resp(200, {"id": 1})
        return _resp(500)

    provider = AzureDevOpsPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/proj/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=new -->\nfresh",
        marker=MARKER_PREFIX, token="t",
    )
    assert "500/comments/1" in patched[0][0]
    assert patched[0][1]["content"].startswith(MARKER_PREFIX)


def test_unauthorized_raises_auth_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return _resp(401)

    provider = AzureDevOpsPrProvider(transport=httpx.MockTransport(handler))
    with pytest.raises(AuthError):
        provider.post_or_update_comment(
            repo="acme-org/proj/api", pr_number=42,
            body="x", marker=MARKER_PREFIX, token="bad",
        )


def test_rejects_malformed_repo_string():
    def handler(req: httpx.Request) -> httpx.Response:
        return _resp(200)

    provider = AzureDevOpsPrProvider(transport=httpx.MockTransport(handler))
    # Azure DevOps requires org/project/repo
    with pytest.raises(ValueError):
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=42,
            body="x", marker=MARKER_PREFIX, token="t",
        )
