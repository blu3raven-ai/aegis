"""Tests for the DB-aware ingester :meth:`BaseIngester.verify_signature`.

``verify_signature`` mirrors the FastAPI receiver's secret-resolution order
so a standalone caller — unit tests, the catalog liveness check, any code
without an open session in hand — gets the same answer the route would.
A configured ``webhook_endpoints`` row wins over the legacy env-var; an
unmatched DB row + no env-var fails closed.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from src.settings.webhooks.service import create_endpoint  # noqa: E402
from src.db.helpers import run_db  # noqa: E402
from src.db.models import WebhookEndpoint  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _cleanup(db_session: AsyncSession):
    yield
    await db_session.execute(delete(WebhookEndpoint))
    await db_session.commit()

    async def _drain(session):
        await session.execute(delete(WebhookEndpoint))

    run_db(_drain)


def _hmac_header(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _basic_header(secret: str) -> str:
    return "Basic " + base64.b64encode(secret.encode()).decode()


def _bearer_header(secret: str) -> str:
    return f"Bearer {secret}"


def _make_header_for(provider: str, body: bytes, secret: str) -> str:
    """Build the wire-format header value the provider expects for ``secret``."""
    if provider in ("github", "bitbucket"):
        return _hmac_header(secret, body)
    if provider == "gitlab":
        return secret
    if provider == "azure_devops":
        return _basic_header(secret)
    if provider == "jenkins":
        return _bearer_header(secret)
    raise AssertionError(f"unknown provider {provider!r}")


def _load_ingester(module_path: str, class_name: str):
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, class_name)()


_PROVIDER_FIXTURES = [
    ("github", "GITHUB_WEBHOOK_SECRET", "src.connectors.webhooks.providers.github", "GitHubIngester"),
    ("gitlab", "GITLAB_WEBHOOK_SECRET", "src.connectors.webhooks.providers.gitlab", "GitLabIngester"),
    ("bitbucket", "BITBUCKET_WEBHOOK_SECRET", "src.connectors.webhooks.providers.bitbucket", "BitbucketIngester"),
    ("azure_devops", "AZURE_DEVOPS_WEBHOOK_SECRET", "src.connectors.webhooks.providers.azure_devops", "AzureDevOpsIngester"),
    ("jenkins", "JENKINS_WEBHOOK_SECRET", "src.connectors.webhooks.providers.jenkins", "JenkinsIngester"),
]


_BODY = b'{"x":1}'


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_accepts_env_var_secret_when_no_db_row(
    monkeypatch, provider, env_var, module_path, class_name
):
    secret = "env-only-secret"
    monkeypatch.setenv(env_var, secret)
    ingester = _load_ingester(module_path, class_name)

    assert ingester.verify_signature(_BODY, _make_header_for(provider, _BODY, secret)) is True


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_accepts_db_secret_when_no_env_var(
    monkeypatch, provider, env_var, module_path, class_name
):
    monkeypatch.delenv(env_var, raising=False)

    async def _seed(session: AsyncSession) -> str:
        payload = await create_endpoint(session, org_id="default", provider=provider)
        return payload["secret"]

    db_secret = run_db(_seed)
    ingester = _load_ingester(module_path, class_name)

    assert ingester.verify_signature(_BODY, _make_header_for(provider, _BODY, db_secret)) is True


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_db_takes_precedence_when_both_configured(
    monkeypatch, provider, env_var, module_path, class_name
):
    """Both DB and env-var configured: signing with the DB secret wins, env-var
    secret still verifies on its own (consistent with the request path)."""
    monkeypatch.setenv(env_var, "env-secret-different-from-db")

    async def _seed(session: AsyncSession) -> str:
        payload = await create_endpoint(session, org_id="default", provider=provider)
        return payload["secret"]

    db_secret = run_db(_seed)
    ingester = _load_ingester(module_path, class_name)

    assert ingester.verify_signature(_BODY, _make_header_for(provider, _BODY, db_secret)) is True
    assert ingester.verify_signature(_BODY, _make_header_for(provider, _BODY, "env-secret-different-from-db")) is True


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_rejects_when_no_secret_configured_anywhere(
    monkeypatch, provider, env_var, module_path, class_name
):
    monkeypatch.delenv(env_var, raising=False)
    ingester = _load_ingester(module_path, class_name)

    assert ingester.verify_signature(_BODY, _make_header_for(provider, _BODY, "any-secret")) is False


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_rejects_wrong_signature_with_env_var_set(
    monkeypatch, provider, env_var, module_path, class_name
):
    """env-var secret is configured but the caller passes a header signed with
    a different secret — rejection must remain timing-safe and unconditional."""
    monkeypatch.setenv(env_var, "the-real-secret")
    ingester = _load_ingester(module_path, class_name)

    forged = _make_header_for(provider, _BODY, "attacker-guess")
    assert ingester.verify_signature(_BODY, forged) is False


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_verify_signature_does_not_leak_secret_in_logs(
    monkeypatch, caplog, provider, env_var, module_path, class_name
):
    """A failed lookup must not surface the candidate plaintext in any log."""
    secret = "ultra-sensitive-secret-do-not-log"
    monkeypatch.setenv(env_var, secret)
    ingester = _load_ingester(module_path, class_name)

    forged = _make_header_for(provider, _BODY, "attacker-guess")
    with caplog.at_level(logging.DEBUG):
        ingester.verify_signature(_BODY, forged)

    for record in caplog.records:
        assert secret not in record.getMessage()
