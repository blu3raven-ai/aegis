"""Tests for the DB-backed webhook secret lookup used by receivers."""
from __future__ import annotations

import os
from typing import Callable

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())

from src.settings.webhooks.service import (  # noqa: E402
    create_endpoint,
    match_webhook_secret,
)
from src.db.models import WebhookEndpoint  # noqa: E402


@pytest_asyncio.fixture(autouse=True)
async def _cleanup(db_session: AsyncSession):
    yield
    await db_session.execute(delete(WebhookEndpoint))
    await db_session.commit()


def _make_verifier(expected: str) -> Callable[[str], bool]:
    """Tiny stand-in for the provider's HMAC/token verifier."""
    return lambda candidate: candidate == expected


@pytest.mark.asyncio
async def test_match_returns_db_secret_when_verifier_accepts(db_session: AsyncSession):
    payload = await create_endpoint(db_session, org_id="default", provider="github")
    await db_session.commit()
    secret = payload["secret"]

    matched = await match_webhook_secret(
        db_session, provider="github", verify=_make_verifier(secret)
    )
    assert matched is not None
    assert matched.secret == secret
    assert matched.org_id == "default"
    assert matched.endpoint_id == payload["id"]


@pytest.mark.asyncio
async def test_match_returns_the_org_whose_secret_verified(db_session: AsyncSession):
    """The match must attribute the request to the org that owns the
    accepting secret — not to any other org configured for the provider."""
    a = await create_endpoint(db_session, org_id="org-a", provider="github")
    b = await create_endpoint(db_session, org_id="org-b", provider="github")
    await db_session.commit()
    target = b["secret"]
    assert a["secret"] != target

    matched = await match_webhook_secret(
        db_session, provider="github", verify=_make_verifier(target)
    )
    assert matched is not None
    assert matched.secret == target
    assert matched.org_id == "org-b"
    assert matched.endpoint_id == b["id"]


@pytest.mark.asyncio
async def test_match_falls_back_to_env_var_when_no_db_row_matches(
    db_session: AsyncSession, monkeypatch
):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "env-fallback-secret")
    matched = await match_webhook_secret(
        db_session, provider="github", verify=_make_verifier("env-fallback-secret")
    )
    assert matched is not None
    assert matched.secret == "env-fallback-secret"
    # Bootstrap env-var has no tenant binding.
    assert matched.org_id is None
    assert matched.endpoint_id is None


@pytest.mark.asyncio
async def test_match_returns_none_when_nothing_verifies(
    db_session: AsyncSession, monkeypatch
):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    await create_endpoint(db_session, org_id="default", provider="github")
    await db_session.commit()

    matched = await match_webhook_secret(
        db_session, provider="github", verify=lambda _: False
    )
    assert matched is None


@pytest.mark.asyncio
async def test_match_unknown_provider_returns_none(db_session: AsyncSession):
    matched = await match_webhook_secret(
        db_session, provider="perforce", verify=lambda _: True
    )
    assert matched is None


@pytest.mark.asyncio
async def test_match_ignores_other_providers(db_session: AsyncSession, monkeypatch):
    monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
    monkeypatch.delenv("GITLAB_WEBHOOK_SECRET", raising=False)
    gitlab_payload = await create_endpoint(
        db_session, org_id="default", provider="gitlab"
    )
    await db_session.commit()

    matched = await match_webhook_secret(
        db_session,
        provider="github",
        verify=_make_verifier(gitlab_payload["secret"]),
    )
    assert matched is None
