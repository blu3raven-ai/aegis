"""SSRF guards on the two save boundaries that previously skipped validation.

A source connection's ``instanceUrl`` and the BYO-LLM ``apiBaseUrl`` are both
persisted and later handed to the runner with a credential (SCM token / LLM
Bearer key). Only the optional ``/test`` actions validated them; the actual
save paths did not, so a caller could store an internal/link-local target and
exfiltrate the credential. These pin the guard on the real save paths.
"""
from __future__ import annotations

import os
import socket
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

import pytest

from src.shared.url_guard import UnsafeURLError
from src.sources.store import SourceValidationError, _reject_unsafe_instance_url
from src.settings.llm.service import LlmConfigUpsert, upsert_llm_config


def _resolves_to(*ips):
    """Fake DNS in the shared guard so tests never touch the network."""
    def fake(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return patch("src.shared.url_guard.socket.getaddrinfo", side_effect=fake)


# ── source instanceUrl (SSRF-01) ─────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["10.0.0.5", "127.0.0.1", "169.254.169.254", "192.168.1.1"])
def test_source_instance_url_rejects_internal(bad):
    with _resolves_to(bad), pytest.raises(SourceValidationError):
        _reject_unsafe_instance_url({"instanceUrl": "https://gitlab.internal", "token": "x"})


def test_source_instance_url_rejects_schemeless_internal():
    # A bare host is normalized to https:// then validated — it must not slip past.
    with _resolves_to("169.254.169.254"), pytest.raises(SourceValidationError):
        _reject_unsafe_instance_url({"instanceUrl": "169.254.169.254"})


def test_source_instance_url_allows_public():
    with _resolves_to("140.82.112.3"):  # public
        _reject_unsafe_instance_url({"instanceUrl": "https://gitlab.example.com", "token": "x"})


def test_source_instance_url_noop_when_absent():
    _reject_unsafe_instance_url({"token": "x"})  # no instanceUrl → no raise, no DNS


# ── LLM apiBaseUrl (SSRF-02) ─────────────────────────────────────────────────

def _upsert(url):
    return LlmConfigUpsert(
        org_id="default", api_key="k", api_base_url=url, model="m",
        scan_token_budget=1000, daily_token_budget=1000, enabled=True,
    )


def test_llm_base_url_rejects_internal_before_persist():
    # The guard fires before any DB write, so this needs no database.
    with _resolves_to("127.0.0.1"), pytest.raises(UnsafeURLError):
        upsert_llm_config(_upsert("https://llm.internal"))
