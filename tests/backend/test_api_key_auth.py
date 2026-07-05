"""Tests for API key authentication (hash verification, revocation, expiry)."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest


@pytest.fixture(scope="session", autouse=True)
def _seed_roles():
    from src.db.helpers import run_db
    from src.db.models import Role
    from src.db.seed import DEFAULT_ROLES

    async def _insert(session):
        for role_data in DEFAULT_ROLES:
            existing = await session.get(Role, role_data["id"])
            if not existing:
                session.add(Role(
                    id=role_data["id"],
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                    protected=role_data["protected"],
                    created_at=datetime.now(timezone.utc),
                ))

    run_db(_insert)


def _create_key_direct(org_id: str, name: str, expires_in_days=None):
    from src.api_keys.service import _create_sync
    return _create_sync(org_id, name, [], "test-user", expires_in_days)


def test_valid_token_authenticates():
    from src.api_keys.auth import _verify_sync
    record, token = _create_key_direct("auth-org", "valid-key")
    row = _verify_sync(f"Bearer {token}")
    assert row is not None
    assert row.id == record.id


def test_wrong_token_returns_none():
    from src.api_keys.auth import _verify_sync
    result = _verify_sync("Bearer ak_live_thisisnotavalidtoken12345678901")
    assert result is None


def test_missing_bearer_returns_none():
    from src.api_keys.auth import _verify_sync
    assert _verify_sync(None) is None
    assert _verify_sync("") is None
    assert _verify_sync("Token something") is None


def test_jwt_format_token_returns_none():
    from src.api_keys.auth import _verify_sync
    result = _verify_sync("Bearer eyJhbGciOiJSUzI1NiJ9.fake.token")
    assert result is None


def test_revoked_token_returns_none():
    from src.api_keys.auth import _verify_sync
    from src.api_keys.service import _revoke_sync
    record, token = _create_key_direct("revoke-auth-org", "revoke-me")
    _revoke_sync(record.id, "revoke-auth-org")
    row = _verify_sync(f"Bearer {token}")
    assert row is None


def test_expired_token_returns_none():
    from src.api_keys.auth import _verify_sync
    from src.db.helpers import run_db
    from src.db.models import ApiKey

    record, token = _create_key_direct("exp-auth-org", "exp-key")

    async def _expire(session):
        row = await session.get(ApiKey, record.id)
        row.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)

    run_db(_expire)
    row = _verify_sync(f"Bearer {token}")
    assert row is None


def test_try_api_key_auth_populates_request_state():
    from src.api_keys.middleware import try_api_key_auth
    from unittest.mock import MagicMock

    record, token = _create_key_direct("state-org", "state-key")
    request = MagicMock()
    request.state = MagicMock()

    row = asyncio.run(try_api_key_auth(request, token))
    assert row is not None
    assert request.state.user_sub == f"api_key:{record.id}"
    assert request.state.user_role == "viewer"
