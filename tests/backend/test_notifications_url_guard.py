"""SSRF guard + destination secret-redaction regression tests.

Hermetic: DNS resolution is monkeypatched so no real network lookup happens.
"""
from __future__ import annotations

import socket

import pytest

from src.notifications.url_guard import UnsafeURLError, assert_sendable_url
from src.notifications.destination import redact_config
from src.notifications.senders.slack import SlackSender
from src.notifications.senders.webhook import GenericWebhookSender


def _fake_getaddrinfo(ip: str):
    """Return a getaddrinfo stub that always resolves to `ip`."""
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _stub(host, port, *args, **kwargs):
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 0))]

    return _stub


def test_guard_rejects_cloud_metadata(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254"))
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("http://169.254.169.254/latest/meta-data/iam/")


def test_guard_rejects_loopback(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("http://127.0.0.1")


def test_guard_rejects_localhost_name(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1"))
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("http://localhost/hook")


def test_guard_rejects_rfc1918(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("10.1.2.3"))
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("http://internal.example/hook")


def test_guard_rejects_non_http_scheme():
    # Scheme is checked before resolution — no monkeypatch needed.
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("file:///etc/passwd")
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("gopher://example.com/")


def test_guard_allows_public_https(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    # Should not raise.
    assert_sendable_url("https://hooks.example.com/services/T/B/xxx")


def test_guard_rejects_when_any_resolved_address_internal(monkeypatch):
    def _mixed(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port or 0)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", port or 0)),
        ]

    monkeypatch.setattr("socket.getaddrinfo", _mixed)
    with pytest.raises(UnsafeURLError):
        assert_sendable_url("https://rebind.example/hook")


def test_webhook_sender_blocks_ssrf_without_posting(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("169.254.169.254"))

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be used for a blocked URL")

    monkeypatch.setattr("src.notifications.senders.webhook.default_client", _boom)
    result = GenericWebhookSender().send({"x": 1}, {"url": "http://169.254.169.254/"})
    assert result.success is False
    assert result.error == "blocked: destination URL is not permitted"


def test_slack_sender_blocks_ssrf_without_posting(monkeypatch):
    monkeypatch.setattr("socket.getaddrinfo", _fake_getaddrinfo("127.0.0.1"))

    def _boom(*args, **kwargs):
        raise AssertionError("HTTP client must not be used for a blocked URL")

    monkeypatch.setattr("src.notifications.senders.slack.default_client", _boom)
    result = SlackSender().send({"text": "hi"}, {"webhook_url": "http://127.0.0.1/hook"})
    assert result.success is False
    assert result.error == "blocked: destination URL is not permitted"


def test_redact_config_masks_secrets_without_mutating_original():
    config = {
        "_signing_secrets": [
            {"raw": "s", "version": 1, "status": "active", "created_at": "t"},
        ],
        "secret": "legacy",
        "webhook_url": "https://hooks.slack.com/services/T00/B00/tokentoken",
    }
    out = redact_config(config)
    entry = out["_signing_secrets"][0]
    assert "raw" not in entry
    assert entry["version"] == 1
    assert entry["status"] == "active"
    assert out["secret"] == "***"
    assert out["webhook_url"] == "https://hooks.slack.com/***"

    # Original stored config must be untouched so signing still works.
    assert config["_signing_secrets"][0]["raw"] == "s"
    assert config["secret"] == "legacy"
    assert config["webhook_url"] == "https://hooks.slack.com/services/T00/B00/tokentoken"


def test_redact_config_strips_url_embedded_credentials():
    out = redact_config({"url": "https://user:pass@webhook.example.com/ingest?x=1"})
    assert out["url"] == "https://webhook.example.com/ingest?x=1"
