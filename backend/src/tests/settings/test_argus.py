"""Tests for the per-org Argus OAuth connection storage, retrieval, and token mint."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import delete, select

os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from src.db.models import ArgusConnection  # noqa: E402
from src.settings.argus import service as svc  # noqa: E402
from src.settings.argus.service import (  # noqa: E402
    ArgusAuthError,
    ArgusConnectionDTO,
    delete_argus_connection,
    fetch_argus_connection,
    mint_argus_access_token,
    upsert_argus_connection,
)


@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid4()}"


async def _cleanup(session, org_id: str) -> None:
    await session.execute(delete(ArgusConnection).where(ArgusConnection.org_id == org_id))
    await session.commit()


@pytest.mark.asyncio
async def test_upsert_then_fetch_round_trips(db_session, org_id):
    try:
        await upsert_argus_connection(
            db_session, org_id,
            endpoint="https://argus.example.ai",
            token_endpoint="https://argus.example.ai/oauth/token",
            client_id="aegis-client",
            refresh_token="argus-refresh-abc",
            enabled=True,
        )
        await db_session.commit()

        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None
        assert conn.endpoint == "https://argus.example.ai"
        assert conn.token_endpoint == "https://argus.example.ai/oauth/token"
        assert conn.client_id == "aegis-client"
        assert conn.refresh_token == "argus-refresh-abc"
        assert conn.enabled is True
    finally:
        await _cleanup(db_session, org_id)


@pytest.mark.asyncio
async def test_refresh_token_is_encrypted_at_rest(db_session, org_id):
    secret = "argus-super-secret-refresh-token"
    try:
        await upsert_argus_connection(
            db_session, org_id,
            endpoint="https://argus.example.ai",
            token_endpoint="https://argus.example.ai/oauth/token",
            client_id="aegis-client",
            refresh_token=secret,
            enabled=False,
        )
        await db_session.commit()

        row = (
            await db_session.execute(
                select(ArgusConnection).where(ArgusConnection.org_id == org_id)
            )
        ).scalar_one()
        assert row.refresh_token_enc != secret
        assert secret not in row.refresh_token_enc

        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None
        assert conn.refresh_token == secret
    finally:
        await _cleanup(db_session, org_id)


@pytest.mark.asyncio
async def test_upsert_updates_existing_row(db_session, org_id):
    try:
        await upsert_argus_connection(
            db_session, org_id,
            endpoint="https://old.example.ai",
            token_endpoint="https://old.example.ai/oauth/token",
            client_id="old", refresh_token="old-rt", enabled=False,
        )
        await db_session.commit()
        await upsert_argus_connection(
            db_session, org_id,
            endpoint="https://new.example.ai",
            token_endpoint="https://new.example.ai/oauth/token",
            client_id="new", refresh_token="new-rt", enabled=True,
        )
        await db_session.commit()

        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None
        assert conn.endpoint == "https://new.example.ai"
        assert conn.refresh_token == "new-rt"
        assert conn.enabled is True
    finally:
        await _cleanup(db_session, org_id)


@pytest.mark.asyncio
async def test_fetch_returns_none_for_unknown_org(db_session):
    assert await fetch_argus_connection(db_session, f"never-existed-{uuid4()}") is None


@pytest.mark.asyncio
async def test_delete_removes_row(db_session, org_id):
    await upsert_argus_connection(
        db_session, org_id,
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="c", refresh_token="rt", enabled=True,
    )
    await db_session.commit()

    deleted = await delete_argus_connection(db_session, org_id)
    await db_session.commit()
    assert deleted is True
    assert await fetch_argus_connection(db_session, org_id) is None

    # Second delete is a no-op.
    assert await delete_argus_connection(db_session, org_id) is False


# --- token mint (sync; the OAuth refresh-token exchange) --------------------

def _dto() -> ArgusConnectionDTO:
    return ArgusConnectionDTO(
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="aegis-client",
        refresh_token="rt-123",
        enabled=True,
    )


def _fake_client(status: int, payload: dict):
    class _Resp:
        status_code = status

        def json(self):
            return payload

    class _Client:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, *a, **kw):
            return _Resp()

    return _Client


def test_mint_returns_access_token(monkeypatch):
    monkeypatch.setattr(svc.httpx, "Client", _fake_client(200, {"access_token": "at_123", "expires_in": 300}))
    assert mint_argus_access_token(_dto()) == "at_123"


def test_mint_raises_on_non_200(monkeypatch):
    monkeypatch.setattr(svc.httpx, "Client", _fake_client(400, {"error": "invalid_grant"}))
    with pytest.raises(ArgusAuthError):
        mint_argus_access_token(_dto())


def test_mint_raises_on_missing_token(monkeypatch):
    monkeypatch.setattr(svc.httpx, "Client", _fake_client(200, {"expires_in": 300}))
    with pytest.raises(ArgusAuthError):
        mint_argus_access_token(_dto())


def test_mint_does_not_echo_refresh_token(monkeypatch):
    monkeypatch.setattr(svc.httpx, "Client", _fake_client(401, {"error": "bad"}))
    try:
        mint_argus_access_token(_dto())
    except ArgusAuthError as exc:
        assert "rt-123" not in str(exc)
