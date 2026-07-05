"""Hosted Argus and the BYO LLM are independent verification providers:
enabling or disabling one never flips the other. Precedence when both are on
lives in scan dispatch (Argus wins), not in the settings writes."""
from __future__ import annotations

import os
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import delete

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())

from src.db.models import ArgusConnection, LlmConfig  # noqa: E402
from src.settings.argus.service import (  # noqa: E402
    fetch_argus_connection,
    upsert_argus_connection,
)
from src.settings.llm.service import (  # noqa: E402
    LlmConfigUpsert,
    fetch_llm_config,
    upsert_llm_config,
)


@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid4()}"


async def _cleanup(session, org_id: str) -> None:
    await session.execute(delete(ArgusConnection).where(ArgusConnection.org_id == org_id))
    await session.execute(delete(LlmConfig).where(LlmConfig.org_id == org_id))
    await session.commit()


async def _enable_argus(session, org_id: str, *, enabled: bool = True) -> None:
    await upsert_argus_connection(
        session, org_id,
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="c", refresh_token="rt", enabled=enabled,
    )
    await session.commit()


def _enable_byo(org_id: str, *, enabled: bool = True) -> None:
    # upsert_llm_config wraps its own run_db (separate connection + commit).
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id, api_key="sk-test", api_base_url="https://api.example.ai/v1",
        model="m", enabled=enabled,
    ))


@pytest.mark.asyncio
async def test_enabling_argus_leaves_byo_enabled(db_session, org_id):
    try:
        _enable_byo(org_id)
        await _enable_argus(db_session, org_id)

        # BYO read on its own connection (always fresh) — still enabled.
        cfg = fetch_llm_config(org_id)
        assert cfg is not None and cfg.enabled is True

        # rollback() drops db_session's snapshot so the re-read reflects the
        # committed state rather than the identity map.
        await db_session.rollback()
        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None and conn.enabled is True
    finally:
        await _cleanup(db_session, org_id)


@pytest.mark.asyncio
async def test_enabling_byo_leaves_argus_enabled(db_session, org_id):
    try:
        await _enable_argus(db_session, org_id)
        _enable_byo(org_id)

        cfg = fetch_llm_config(org_id)
        assert cfg is not None and cfg.enabled is True

        await db_session.rollback()
        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None and conn.enabled is True
    finally:
        await _cleanup(db_session, org_id)


@pytest.mark.asyncio
async def test_disabling_one_leaves_the_other_untouched(db_session, org_id):
    try:
        _enable_byo(org_id)
        await _enable_argus(db_session, org_id)                  # both on
        await _enable_argus(db_session, org_id, enabled=False)   # Argus -> off

        # BYO is unaffected by turning Argus off.
        cfg = fetch_llm_config(org_id)
        assert cfg is not None and cfg.enabled is True
        await db_session.rollback()
        conn = await fetch_argus_connection(db_session, org_id)
        assert conn is not None and conn.enabled is False
    finally:
        await _cleanup(db_session, org_id)
