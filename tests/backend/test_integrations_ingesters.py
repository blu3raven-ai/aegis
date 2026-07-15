"""Pin the contract of the four webhook ingesters (3 SCM + Argus).

Each ingester must: register under a stable id, expose the right signature
header name, and route signature verification through the correct env var
+ kernel primitive."""
from __future__ import annotations

import hashlib
import hmac

import pytest

from src.connectors.registry import get_connector


@pytest.fixture(autouse=True)
def _ensure_ingesters_registered(reset_and_reload_connectors):
    """Ensure ingester classes are in the registry before each test.

    A plain import is a no-op once the module is in sys.modules, and another
    test module may have called _reset_registry() in teardown, so the shared
    helper resets and reloads to re-run the @register_connector decorators.
    """
    reset_and_reload_connectors(
        "src.connectors.webhooks.providers.github",
        "src.connectors.webhooks.providers.gitlab",
        "src.connectors.webhooks.providers.bitbucket",
        "src.connectors.webhooks.providers.argus",
    )
    yield


def _hmac_header(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()



def test_github_ingester_registered():
    from src.connectors.webhooks.providers import github as _gh
    cls = get_connector("github-webhook")
    assert cls is _gh.GitHubIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"
    assert cls.icon_slug == "github"


def test_github_signature_header_name():
    from src.connectors.webhooks.providers import github as _gh
    assert _gh.GitHubIngester().signature_header() == "X-Hub-Signature-256"


def test_github_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import github as _gh
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "gh-secret")
    body = b'{"x":1}'
    ing = _gh.GitHubIngester()
    assert ing.verify_signature(body, _hmac_header("gh-secret", body)) is True
    assert ing.verify_signature(body, _hmac_header("wrong", body)) is False


def test_github_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import github as _gh
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    assert _gh.GitHubIngester().verify_signature(b"x", _hmac_header("any", b"x")) is False


def test_github_test_method_reports_secret_missing(monkeypatch):
    from src.connectors.webhooks.providers import github as _gh
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    result = _gh.GitHubIngester().test()
    assert result.ok is False
    assert "GITHUB_WEBHOOK_SECRET" in (result.message or "")



def test_gitlab_ingester_registered():
    from src.connectors.webhooks.providers import gitlab as _gl
    cls = get_connector("gitlab-webhook")
    assert cls is _gl.GitLabIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"


def test_gitlab_signature_header_name():
    from src.connectors.webhooks.providers import gitlab as _gl
    assert _gl.GitLabIngester().signature_header() == "X-Gitlab-Token"


def test_gitlab_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import gitlab as _gl
    monkeypatch.setenv("GITLAB_WEBHOOK_SECRET", "gl-token")
    ing = _gl.GitLabIngester()
    assert ing.verify_signature(b"body-ignored", "gl-token") is True
    assert ing.verify_signature(b"body-ignored", "wrong") is False


def test_gitlab_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import gitlab as _gl
    monkeypatch.delenv("GITLAB_WEBHOOK_SECRET", raising=False)
    assert _gl.GitLabIngester().verify_signature(b"x", "anything") is False



def test_bitbucket_ingester_registered():
    from src.connectors.webhooks.providers import bitbucket as _bb
    cls = get_connector("bitbucket-webhook")
    assert cls is _bb.BitbucketIngester
    assert cls.kind == "ingester"
    assert cls.category == "ci"


def test_bitbucket_signature_header_name():
    from src.connectors.webhooks.providers import bitbucket as _bb
    assert _bb.BitbucketIngester().signature_header() == "X-Hub-Signature"


def test_bitbucket_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import bitbucket as _bb
    monkeypatch.setenv("BITBUCKET_WEBHOOK_SECRET", "bb-secret")
    body = b'{"x":1}'
    ing = _bb.BitbucketIngester()
    assert ing.verify_signature(body, _hmac_header("bb-secret", body)) is True
    assert ing.verify_signature(body, _hmac_header("wrong", body)) is False


def test_bitbucket_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import bitbucket as _bb
    monkeypatch.delenv("BITBUCKET_WEBHOOK_SECRET", raising=False)
    assert _bb.BitbucketIngester().verify_signature(b"x", _hmac_header("any", b"x")) is False



def test_argus_ingester_registered():
    from src.connectors.webhooks.providers import argus as _ar
    cls = get_connector("argus-webhook")
    assert cls is _ar.ArgusIngester
    assert cls.kind == "ingester"
    assert cls.category == "intel"
    assert cls.icon_slug == "argus"


def test_argus_signature_header_name():
    from src.connectors.webhooks.providers import argus as _ar
    assert _ar.ArgusIngester().signature_header() == "X-Argus-Signature"


def test_argus_verify_signature_routes_through_env(monkeypatch):
    from src.connectors.webhooks.providers import argus as _ar
    monkeypatch.setenv("ARGUS_WEBHOOK_SECRET", "argus-secret")
    body = b'{"event_type":"cve_published"}'
    ing = _ar.ArgusIngester()
    assert ing.verify_signature(body, _hmac_header("argus-secret", body)) is True
    assert ing.verify_signature(body, _hmac_header("wrong", body)) is False


def test_argus_verify_signature_env_missing_fails_closed(monkeypatch):
    from src.connectors.webhooks.providers import argus as _ar
    monkeypatch.delenv("ARGUS_WEBHOOK_SECRET", raising=False)
    assert _ar.ArgusIngester().verify_signature(b"x", _hmac_header("any", b"x")) is False


def test_argus_test_method_reports_secret_missing(monkeypatch):
    from src.connectors.webhooks.providers import argus as _ar
    monkeypatch.delenv("ARGUS_WEBHOOK_SECRET", raising=False)
    result = _ar.ArgusIngester().test()
    assert result.ok is False
    assert "ARGUS_WEBHOOK_SECRET" in (result.message or "")


def test_normalize_returns_parsed_json():
    """All four ingesters implement normalize as JSON parsing."""
    from src.connectors.webhooks.providers import argus as _ar
    from src.connectors.webhooks.providers import github as _gh
    from src.connectors.webhooks.providers import gitlab as _gl
    from src.connectors.webhooks.providers import bitbucket as _bb
    body = b'{"hello":"world"}'
    for ingester_cls in (
        _gh.GitHubIngester, _gl.GitLabIngester, _bb.BitbucketIngester, _ar.ArgusIngester,
    ):
        assert ingester_cls().normalize(body) == {"hello": "world"}
