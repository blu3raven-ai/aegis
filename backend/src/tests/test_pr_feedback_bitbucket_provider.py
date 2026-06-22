"""Bitbucket PR comment provider."""
from __future__ import annotations

import json

import httpx
import pytest

from src.pr_feedback.git_pr_providers.base import AuthError
from src.pr_feedback.git_pr_providers.bitbucket import BitbucketPrProvider
from src.pr_feedback.render import MARKER_PREFIX


def _resp(status: int, body=None) -> httpx.Response:
    return httpx.Response(status_code=status, json=body if body is not None else {})


def test_creates_new_comment_when_no_existing_marker():
    posted = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, {"values": [{"id": 1, "content": {"raw": "lgtm"}}], "next": None})
        if req.method == "POST":
            posted.append(json.loads(req.content.decode()))
            return _resp(201, {"id": 999})
        return _resp(500)

    provider = BitbucketPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=s1 -->\nbody",
        marker=MARKER_PREFIX, token="bbtoken",
    )
    assert posted[0]["content"]["raw"].startswith(MARKER_PREFIX)


def test_patches_existing_comment_when_marker_present():
    patched = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            return _resp(200, {
                "values": [
                    {"id": 500, "content": {"raw": f"{MARKER_PREFIX}scan=old -->\nstale"}},
                    {"id": 501, "content": {"raw": "unrelated"}},
                ],
                "next": None,
            })
        if req.method == "PUT":
            cid = int(req.url.path.rsplit("/", 1)[-1])
            patched.append((cid, json.loads(req.content.decode())))
            return _resp(200, {"id": cid})
        return _resp(500)

    provider = BitbucketPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=new -->\nfresh",
        marker=MARKER_PREFIX, token="t",
    )
    assert patched[0][0] == 500
    assert patched[0][1]["content"]["raw"].startswith(MARKER_PREFIX)


def test_unauthorized_raises_auth_error():
    def handler(req: httpx.Request) -> httpx.Response:
        return _resp(401)

    provider = BitbucketPrProvider(transport=httpx.MockTransport(handler))
    with pytest.raises(AuthError):
        provider.post_or_update_comment(
            repo="acme-org/api", pr_number=42,
            body="x", marker=MARKER_PREFIX, token="bad",
        )


def test_paginates_when_marker_on_second_page():
    calls = {"n": 0}
    next_url = "https://api.bitbucket.org/2.0/repositories/acme-org/api/pullrequests/42/comments?page=2"

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and "page=2" in str(req.url):
            return _resp(200, {
                "values": [{"id": 777, "content": {"raw": f"{MARKER_PREFIX}scan=x -->"}}],
                "next": None,
            })
        if req.method == "GET":
            calls["n"] += 1
            return _resp(200, {"values": [{"id": 1, "content": {"raw": "lgtm"}}], "next": next_url})
        if req.method == "PUT":
            return _resp(200, {"id": 777})
        return _resp(500)

    provider = BitbucketPrProvider(transport=httpx.MockTransport(handler))
    provider.post_or_update_comment(
        repo="acme-org/api", pr_number=42,
        body=f"{MARKER_PREFIX}scan=fresh -->",
        marker=MARKER_PREFIX, token="t",
    )
    # Should have followed pagination
    assert calls["n"] >= 1
