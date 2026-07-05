"""SSRF-guard regression tests for admin-configured settings fetch sites.

Covers the three server-side fetches of an admin-supplied URL — SAML metadata
refresh, LLM test-connection, Argus test-connection. Hermetic: DNS resolution
and the HTTP clients are monkeypatched so no real lookup or request happens, and
a blocked URL must never reach the HTTP client at all.
"""
from __future__ import annotations

import socket
import types

import pytest
from fastapi import HTTPException

# Proves the guard is reachable via the relocated shared module.
from src.shared.url_guard import UnsafeURLError, assert_sendable_url


def _getaddrinfo_to(ip: str):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _stub(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))]

    return _stub


def test_shared_guard_rejects_metadata_and_allows_public(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("169.254.169.254"))
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("http://169.254.169.254/latest/meta-data/")

    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("93.184.216.34"))
    assert_sendable_url("https://idp.example.com/metadata")  # should not raise


# --- SAML metadata refresh (SSRF-01) -------------------------------------

def _call_saml_refresh():
    """Invoke the raw handler, bypassing the @audited wrapper."""
    from src.settings.sso import router as sso_router

    return sso_router.refresh_saml_metadata.__wrapped__(request=None, _=None)


def test_saml_refresh_blocks_unsafe_url(monkeypatch):
    import asyncio

    from src.settings.sso import router as sso_router

    fake_row = types.SimpleNamespace(
        saml_metadata_url="http://169.254.169.254/meta", saml_metadata_xml=None
    )

    async def _fake_singleton(session):
        return fake_row

    monkeypatch.setattr(sso_router, "_get_singleton", _fake_singleton)
    monkeypatch.setattr(sso_router, "run_db", lambda coro_fn: asyncio.run(coro_fn(None)))
    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("169.254.169.254"))

    import httpx

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be constructed for a blocked URL")

    monkeypatch.setattr(httpx, "AsyncClient", _boom)

    with pytest.raises(HTTPException) as excinfo:
        _call_saml_refresh()
    assert excinfo.value.status_code == 400


def test_saml_refresh_public_url_passes_guard(monkeypatch):
    import asyncio

    from src.settings.sso import router as sso_router

    fake_row = types.SimpleNamespace(
        saml_metadata_url="https://idp.example.com/meta", saml_metadata_xml=None
    )

    async def _fake_singleton(session):
        return fake_row

    monkeypatch.setattr(sso_router, "_get_singleton", _fake_singleton)
    monkeypatch.setattr(sso_router, "run_db", lambda coro_fn: asyncio.run(coro_fn(None)))
    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("93.184.216.34"))

    import httpx

    class _Resp:
        text = "<EntityDescriptor/>"

        def raise_for_status(self):
            return None

    class _Client:
        def __init__(self, *args, **kwargs):
            # Redirect-following would let an allowlisted host 302 into an
            # internal target, so the guard's protection is only sound with it off.
            assert kwargs.get("follow_redirects") is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, url):
            return _Resp()

    monkeypatch.setattr(httpx, "AsyncClient", _Client)

    result = _call_saml_refresh()
    assert result.status_code == 200
    assert fake_row.saml_metadata_xml == "<EntityDescriptor/>"


# --- LLM test-connection (SSRF-02a) --------------------------------------

def test_llm_test_connection_blocks_unsafe_url(monkeypatch):
    from src.settings.llm import router as llm_router
    from src.settings.llm.service import LlmConfigDTO

    cfg = LlmConfigDTO(
        org_id="default",
        api_key="sk-test",
        api_base_url="http://127.0.0.1:11434/v1",
        model="m",
        scan_token_budget=1000,
        daily_token_budget=10000,
        enabled=True,
    )
    monkeypatch.setattr(llm_router, "fetch_llm_config", lambda org_id: cfg)
    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("127.0.0.1"))

    import httpx

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be constructed for a blocked URL")

    monkeypatch.setattr(httpx, "Client", _boom)

    result = llm_router.test_llm_connection(request=None, _=None)
    assert result["ok"] is False
    assert result["error"] == "unsafe_url"


# --- Argus test-connection (SSRF-02b) ------------------------------------

def test_argus_test_connection_blocks_unsafe_url(monkeypatch):
    from src.settings.argus import router as argus_router

    conn = types.SimpleNamespace(endpoint="http://169.254.169.254")
    monkeypatch.setattr(argus_router, "run_db", lambda fn: conn)
    monkeypatch.setattr(argus_router, "mint_argus_access_token", lambda c: "tok")
    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("169.254.169.254"))

    import httpx

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be constructed for a blocked URL")

    monkeypatch.setattr(httpx, "Client", _boom)

    result = argus_router.test_argus_connection(request=None, _=None)
    assert result["ok"] is False
    assert result["error"] == "unsafe_url"


# --- OIDC discovery (additional site) ------------------------------------


def test_oidc_discovery_blocks_unsafe_url(monkeypatch):
    import asyncio

    import src.auth.federation.oidc as oidc

    monkeypatch.setattr("socket.getaddrinfo", _getaddrinfo_to("127.0.0.1"))

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be constructed for a blocked URL")

    monkeypatch.setattr(oidc.httpx, "AsyncClient", _boom)

    with pytest.raises(UnsafeURLError):
        asyncio.run(
            oidc._discovery("http://127.0.0.1/.well-known/openid-configuration")
        )
