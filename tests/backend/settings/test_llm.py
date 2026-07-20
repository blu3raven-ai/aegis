"""Tests for per-org BYO LLM credential storage and retrieval."""
from __future__ import annotations

import os
from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

os.environ.setdefault("APP_SECRET", Fernet.generate_key().decode())

from src.settings.llm.service import (  # noqa: E402
    LlmConfigUpsert,
    fetch_llm_config,
    fetch_public_llm_config,
    upsert_llm_config,
)


@pytest.fixture(autouse=True)
def _allow_llm_base_url():
    """These tests exercise storage/response shape, not the SSRF guard, so
    neutralize the base-URL validation for their placeholder URLs."""
    with patch("src.settings.llm.service.assert_sendable_url", lambda *_a, **_k: None):
        yield


@pytest.fixture
def org_id() -> str:
    return f"test-org-{uuid4()}"


def test_upsert_stores_encrypted_key(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-test-abc",
        api_base_url="https://api.example.ai/v1",
        model="claude-sonnet-4-6",
    ))
    cfg = fetch_llm_config(org_id)
    assert cfg is not None
    assert cfg.api_key == "sk-test-abc"
    assert cfg.api_base_url == "https://api.example.ai/v1"
    assert cfg.model == "claude-sonnet-4-6"
    assert cfg.enabled is False


def test_fetch_returns_none_for_unknown_org(db_session):
    assert fetch_llm_config(f"never-existed-{uuid4()}") is None


def test_public_view_omits_api_key(db_session, org_id):
    upsert_llm_config(LlmConfigUpsert(
        org_id=org_id,
        api_key="sk-secret",
        api_base_url="https://x",
        model="m",
    ))
    pub = fetch_public_llm_config(org_id)
    assert pub is not None
    assert "api_key" not in pub
    assert pub["configured"] is True
