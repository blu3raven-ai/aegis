"""Unit tests for the scanner HTTP client helper (Phase 7, Step 1).

These tests cover URL resolution, transport-mode toggling, request/response
plumbing, and the workspace URI translation contract. All HTTP traffic is
stubbed via httpx.MockTransport — no real network or scanner container needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from src.shared.scanner_http_client import (
    CHECKOUT_TRANSPORT_ENV,
    AdapterFailedError,
    AdapterUnavailableError,
    ScannerHttpClient,
    checkout_path_to_workspace_uri,
    resolve_base_url,
)


# ─── URL resolution ─────────────────────────────────────────────────────────


class TestResolveBaseUrl:
    def test_returns_url_when_env_set(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps.scanner:8081")
        assert resolve_base_url("dependencies") == "http://deps.scanner:8081"

    def test_supports_all_four_scanner_types(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://d:1")
        monkeypatch.setenv("SCANNER_CONTAINER_URL", "http://c:2")
        monkeypatch.setenv("SCANNER_SAST_URL", "http://s:3")
        monkeypatch.setenv("SCANNER_SECRETS_URL", "http://x:4")

        assert resolve_base_url("dependencies") == "http://d:1"
        assert resolve_base_url("container") == "http://c:2"
        assert resolve_base_url("sast") == "http://s:3"
        assert resolve_base_url("secrets") == "http://x:4"

    def test_missing_env_raises_value_error(self, monkeypatch):
        monkeypatch.delenv("SCANNER_DEPS_URL", raising=False)
        with pytest.raises(ValueError, match="SCANNER_DEPS_URL"):
            resolve_base_url("dependencies")

    def test_unknown_scanner_type_raises(self):
        with pytest.raises(ValueError, match="unknown scanner type"):
            resolve_base_url("nonsense")

    def test_strips_trailing_slash(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081/")
        assert resolve_base_url("dependencies") == "http://deps:8081"


# ─── Path → URI translation ─────────────────────────────────────────────────


class TestCheckoutPathToWorkspaceUri:
    def test_translates_workspace_path_to_uri(self):
        uri = checkout_path_to_workspace_uri(Path("/workspace/scan-123/repo-abc"))
        assert uri == "workspace://scan-123/repo-abc"

    def test_translates_deep_path(self):
        uri = checkout_path_to_workspace_uri(Path("/workspace/scan-123/sub/dir"))
        assert uri == "workspace://scan-123/sub/dir"

    def test_rejects_path_outside_workspace(self):
        with pytest.raises(ValueError, match="must be under /workspace"):
            checkout_path_to_workspace_uri(Path("/tmp/foo"))

    def test_rejects_workspace_root(self):
        # /workspace alone has no scan_id/repo segments
        with pytest.raises(ValueError):
            checkout_path_to_workspace_uri(Path("/workspace"))

    def test_rejects_traversal_attempt(self):
        with pytest.raises(ValueError):
            checkout_path_to_workspace_uri(Path("/workspace/../etc/passwd"))


# ─── Transport-mode env toggle ──────────────────────────────────────────────


class TestCheckoutTransportMode:
    def test_default_transport_is_minio(self, monkeypatch):
        from src.shared.scanner_http_client import get_checkout_transport
        monkeypatch.delenv(CHECKOUT_TRANSPORT_ENV, raising=False)
        assert get_checkout_transport() == "minio"

    def test_mount_override(self, monkeypatch):
        from src.shared.scanner_http_client import get_checkout_transport
        monkeypatch.setenv(CHECKOUT_TRANSPORT_ENV, "mount")
        assert get_checkout_transport() == "mount"

    def test_unknown_value_raises(self, monkeypatch):
        from src.shared.scanner_http_client import get_checkout_transport
        monkeypatch.setenv(CHECKOUT_TRANSPORT_ENV, "ftp")
        with pytest.raises(ValueError, match="CHECKOUT_TRANSPORT"):
            get_checkout_transport()


# ─── post_json: success and error mapping ───────────────────────────────────


def _stub_transport(handler):
    return httpx.MockTransport(handler)


class TestPostJsonSuccess:
    def test_returns_parsed_json_on_200(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request: httpx.Request) -> httpx.Response:
            assert request.url.path == "/v1/sbom"
            assert json.loads(request.content) == {"checkout_ref": "workspace://a/b"}
            return httpx.Response(200, json={"sbom": {"bomFormat": "CycloneDX"}})

        client = ScannerHttpClient(transport=_stub_transport(handler))
        result = client.post_json(
            "dependencies", "/v1/sbom", {"checkout_ref": "workspace://a/b"}
        )
        assert result == {"sbom": {"bomFormat": "CycloneDX"}}


class TestPostJsonErrors:
    def test_404_raises_failed(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(404, json={"detail": "not found"})

        client = ScannerHttpClient(transport=_stub_transport(handler))
        with pytest.raises(AdapterFailedError) as exc:
            client.post_json("dependencies", "/v1/sbom", {})
        assert exc.value.returncode == 404

    def test_500_raises_failed(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(500, text="boom")

        client = ScannerHttpClient(transport=_stub_transport(handler))
        with pytest.raises(AdapterFailedError):
            client.post_json("dependencies", "/v1/sbom", {})

    def test_503_raises_unavailable(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(503, text="overloaded")

        client = ScannerHttpClient(transport=_stub_transport(handler))
        with pytest.raises(AdapterUnavailableError):
            client.post_json("dependencies", "/v1/sbom", {})

    def test_connect_error_raises_unavailable(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            raise httpx.ConnectError("cannot connect")

        client = ScannerHttpClient(transport=_stub_transport(handler))
        with pytest.raises(AdapterUnavailableError):
            client.post_json("dependencies", "/v1/sbom", {})

    def test_malformed_json_raises_failed(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(
                200,
                content=b"not json at all",
                headers={"content-type": "application/json"},
            )

        client = ScannerHttpClient(transport=_stub_transport(handler))
        with pytest.raises(AdapterFailedError, match="malformed json"):
            client.post_json("dependencies", "/v1/sbom", {})

    def test_missing_env_raises_value_error(self, monkeypatch):
        monkeypatch.delenv("SCANNER_DEPS_URL", raising=False)

        client = ScannerHttpClient(transport=_stub_transport(lambda r: httpx.Response(200)))
        with pytest.raises(ValueError):
            client.post_json("dependencies", "/v1/sbom", {})


# ─── Connection pooling ─────────────────────────────────────────────────────


class TestConnectionPooling:
    """ScannerHttpClient must hold a single long-lived httpx.Client so that
    successive requests share the TCP/TLS connection pool — otherwise each
    call to a warm scanner re-pays the handshake.
    """

    def test_reuses_single_httpx_client_across_calls(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(200, json={"ok": True})

        client = ScannerHttpClient(transport=_stub_transport(handler))
        underlying_first = client._client
        client.post_json("dependencies", "/v1/sbom", {})
        client.post_json("dependencies", "/v1/sbom", {})
        # Same client instance across calls — no per-call construction.
        assert client._client is underlying_first

    def test_context_manager_closes_client(self, monkeypatch):
        monkeypatch.setenv("SCANNER_DEPS_URL", "http://deps:8081")

        def handler(request):
            return httpx.Response(200, json={"ok": True})

        with ScannerHttpClient(transport=_stub_transport(handler)) as client:
            assert not client._client.is_closed
        assert client._client.is_closed

    def test_close_method_closes_client(self, monkeypatch):
        client = ScannerHttpClient(
            transport=_stub_transport(lambda r: httpx.Response(200))
        )
        assert not client._client.is_closed
        client.close()
        assert client._client.is_closed
