"""Pin the contract of the three SCM webhook ingesters.

Each ingester must: register under a stable id, expose the right signature
header name, and route signature verification through the correct env var
+ kernel primitive."""
from __future__ import annotations

import hashlib
import hmac

import pytest

from src.connectors.registry import get_connector


@pytest.fixture(autouse=True)
def _ensure_ingesters_registered():
    """Ensure integrations are imported (and thus @register_connector runs).

    Must run before each test so the registry has the ingester classes.
    """
    # Importing triggers the @register_connector decorator.
    from src.integrations import github_webhook as _gh
    from src.integrations import gitlab_webhook as _gl
    from src.integrations import bitbucket_webhook as _bb
    yield


def _hmac_header(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ── GitHub ──────────────────────────────────────────────────────────────────

def test_github_ingester_registered():
    from src.integrations import github_webhook as _gh
    cls = get_connector("github-webhook")
    assert cls is _gh.GitHubIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"
    assert cls.icon_slug == "github"


def test_github_signature_header_name():
    from src.integrations import github_webhook as _gh
    assert _gh.GitHubIngester().signature_header() == "X-Hub-Signature-256"


def test_github_verify_signature_routes_through_env(monkeypatch):
    from src.integrations import github_webhook as _gh
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
    body = b'{"x":1}'
    ing = _gh.GitHubIngester()
    assert ing.verify_signature(body, _hmac_header("gh-secret", body)) is True
    assert ing.verify_signature(body, _hmac_header("wrong", body)) is False


def test_github_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.integrations import github_webhook as _gh
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    assert _gh.GitHubIngester().verify_signature(b"x", _hmac_header("any", b"x")) is False


def test_github_test_method_reports_secret_missing(monkeypatch):
    from src.integrations import github_webhook as _gh
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    result = _gh.GitHubIngester().test()
    assert result.ok is False
    assert "GITHUB_WEBHOOK_SECRET" in (result.message or "")


# ── GitLab ──────────────────────────────────────────────────────────────────

def test_gitlab_ingester_registered():
    from src.integrations import gitlab_webhook as _gl
    cls = get_connector("gitlab-webhook")
    assert cls is _gl.GitLabIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"


def test_gitlab_signature_header_name():
    from src.integrations import gitlab_webhook as _gl
    assert _gl.GitLabIngester().signature_header() == "X-Gitlab-Token"


def test_gitlab_verify_signature_routes_through_env(monkeypatch):
    from src.integrations import gitlab_webhook as _gl
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "gl-token")
    ing = _gl.GitLabIngester()
    assert ing.verify_signature(b"body-ignored", "gl-token") is True
    assert ing.verify_signature(b"body-ignored", "wrong") is False


def test_gitlab_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.integrations import gitlab_webhook as _gl
    monkeypatch.delenv("GITLAB_WEBHOOK_SECRET", raising=False)
    assert _gl.GitLabIngester().verify_signature(b"x", "anything") is False


# ── Bitbucket ───────────────────────────────────────────────────────────────

def test_bitbucket_ingester_registered():
    from src.integrations import bitbucket_webhook as _bb
    cls = get_connector("bitbucket-webhook")
    assert cls is _bb.BitbucketIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"


def test_bitbucket_signature_header_name():
    from src.integrations import bitbucket_webhook as _bb
    assert _bb.BitbucketIngester().signature_header() == "X-Hub-Signature"


def test_bitbucket_verify_signature_routes_through_env(monkeypatch):
    from src.integrations import bitbucket_webhook as _bb
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
    body = b'{"x":1}'
    ing = _bb.BitbucketIngester()
    assert ing.verify_signature(body, _hmac_header("bb-secret", body)) is True
    assert ing.verify_signature(body, _hmac_header("wrong", body)) is False


def test_bitbucket_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.integrations import bitbucket_webhook as _bb
    monkeypatch.delenv("BITBUCKET_WEBHOOK_SECRET", raising=False)
    assert _bb.BitbucketIngester().verify_signature(b"x", _hmac_header("any", b"x")) is False


# ── Generic normalize() default ────────────────────────────────────────────

def test_normalize_returns_parsed_json():
    """All three ingesters implement normalize as JSON parsing."""
    from src.integrations import github_webhook as _gh
    from src.integrations import gitlab_webhook as _gl
    from src.integrations import bitbucket_webhook as _bb
    body = b'{"hello":"world"}'
    for ingester_cls in (_gh.GitHubIngester, _gl.GitLabIngester, _bb.BitbucketIngester):
        assert ingester_cls().normalize(body) == {"hello": "world"}
