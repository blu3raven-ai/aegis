"""Unit coverage for the legacy-URL redirect middleware.

These 308s move stale /settings/sources/* bookmarks to the new /sources/*
locations. The middleware runs before the auth gate, so a wrong rewrite would
silently strand users (or, worse, an over-broad pattern could capture unrelated
paths). Drive dispatch() directly with a stub request/call_next.
"""
from __future__ import annotations

import types

import pytest

from src.auth.authentication.redirects import LegacyRedirectMiddleware


def _request(path: str):
    return types.SimpleNamespace(url=types.SimpleNamespace(path=path))


async def _passthrough_sentinel(_request):
    return "PASSED_THROUGH"


def _mw():
    # BaseHTTPMiddleware needs an app arg; dispatch never calls into it here.
    return LegacyRedirectMiddleware(app=lambda *a, **k: None)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,expected",
    [
        ("/settings/sources/code-repositories", "/sources/code-repositories"),
        ("/settings/sources/code-repositories/", "/sources/code-repositories"),
        ("/settings/sources/code-repositories/abc123", "/sources/code-repositories/abc123"),
        ("/settings/sources/container-images", "/sources/container-registry"),
        ("/settings/sources/container-images/", "/sources/container-registry"),
        ("/settings/sources/container-images/xyz", "/sources/container-registry/xyz"),
        # ci-cd-pipelines drops any sub-path (matches the old Next.js behavior).
        ("/settings/sources/ci-cd-pipelines", "/sources/code-repositories"),
        ("/settings/sources/ci-cd-pipelines/anything/here", "/sources/code-repositories"),
    ],
)
async def test_matching_paths_redirect_308(path, expected):
    resp = await _mw().dispatch(_request(path), _passthrough_sentinel)
    assert resp.status_code == 308
    assert resp.headers["location"] == expected


@pytest.mark.asyncio
async def test_id_is_preserved_in_rewrite():
    resp = await _mw().dispatch(
        _request("/settings/sources/code-repositories/team%2Frepo"),
        _passthrough_sentinel,
    )
    assert resp.status_code == 308
    assert resp.headers["location"] == "/sources/code-repositories/team%2Frepo"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path",
    [
        "/sources/code-repositories",  # already-new path is untouched
        "/settings/sources",  # parent, no rule
        "/settings/sources/code-repositories/a/b",  # extra segment, no id rule match
        "/dashboard",
        "/",
    ],
)
async def test_non_matching_paths_pass_through(path):
    out = await _mw().dispatch(_request(path), _passthrough_sentinel)
    assert out == "PASSED_THROUGH"


@pytest.mark.asyncio
async def test_id_pattern_does_not_swallow_nested_subpaths():
    # The `[^/]+` id group must not match a path with a further slash — that
    # should fall through, not redirect to a mangled target.
    out = await _mw().dispatch(
        _request("/settings/sources/container-images/x/y"), _passthrough_sentinel
    )
    assert out == "PASSED_THROUGH"
