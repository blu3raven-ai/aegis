"""Tests for the DB-aware ingester ``test()`` healthcheck.

The healthcheck mirrors the receiver path: a configured ``webhook_endpoints``
row takes precedence over the env-var so a rotated secret doesn't surface
as "not configured" in the admin UI.
"""
from __future__ import annotations

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


_PROVIDER_FIXTURES = [
    ("github", "GITHUB_WEBHOOK_SECRET", "src.connectors.webhooks.providers.github", "GitHubIngester"),
    ("gitlab", "GITLAB_WEBHOOK_SECRET", "src.connectors.webhooks.providers.gitlab", "GitLabIngester"),
    ("bitbucket", "BITBUCKET_WEBHOOK_SECRET", "src.connectors.webhooks.providers.bitbucket", "BitbucketIngester"),
    ("azure_devops", "AZURE_DEVOPS_WEBHOOK_SECRET", "src.connectors.webhooks.providers.azure_devops", "AzureDevOpsIngester"),
    ("jenkins", "JENKINS_WEBHOOK_SECRET", "src.connectors.webhooks.providers.jenkins", "JenkinsIngester"),
]


def _load_ingester(module_path: str, class_name: str):
    import importlib

    module = importlib.import_module(module_path)
    return getattr(module, class_name)()


@pytest_asyncio.fixture(autouse=True)
async def _cleanup(db_session: AsyncSession):
    yield
    await db_session.execute(delete(WebhookEndpoint))
    await db_session.commit()

    async def _drain(session):
        await session.execute(delete(WebhookEndpoint))

    run_db(_drain)


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_healthcheck_reports_not_configured_when_no_db_row_and_no_env(
    monkeypatch, provider, env_var, module_path, class_name
):
    monkeypatch.delenv(env_var, raising=False)
    ingester = _load_ingester(module_path, class_name)

    result = ingester.test()
    assert result.ok is False
    assert env_var in (result.message or "")


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_healthcheck_reports_env_var_when_no_db_row_and_env_set(
    monkeypatch, provider, env_var, module_path, class_name
):
    monkeypatch.setenv(env_var, "env-value")
    ingester = _load_ingester(module_path, class_name)

    result = ingester.test()
    assert result.ok is True
    assert "env-var" in (result.message or "")
    assert env_var in (result.message or "")


@pytest.mark.parametrize("provider,env_var,module_path,class_name", _PROVIDER_FIXTURES)
def test_healthcheck_reports_db_backed_when_endpoint_row_exists(
    monkeypatch, provider, env_var, module_path, class_name
):
    # env-var also set to prove DB takes precedence
    monkeypatch.setenv(env_var, "env-value")

    async def _seed(session: AsyncSession):
        await create_endpoint(session, org_id="default", provider=provider)

    run_db(_seed)

    ingester = _load_ingester(module_path, class_name)
    result = ingester.test()
    assert result.ok is True
    assert "DB-backed" in (result.message or "")
