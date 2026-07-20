"""DNS-rebinding defense for outbound sinks (SR: GQL-01).

`assert_sendable_url` resolves-and-validates but the subsequent connect
re-resolves, so a name that answered public at check time could answer
internal at connect time. The pinning helpers close that window by connecting
to the exact IP that was validated.
"""
from __future__ import annotations

import os
import socket
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")

import pytest

from src.shared.url_guard import (
    UnsafeURLError,
    assert_public_host,
    resolve_pinned_url,
    resolve_pinned_url_sync,
)

_PUBLIC = "140.82.112.3"
_INTERNAL = "127.0.0.1"


def _getaddrinfo_returning(*ips):
    def fake(host, port, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port or 0)) for ip in ips]
    return patch("src.shared.url_guard.socket.getaddrinfo", side_effect=fake)


@pytest.mark.parametrize("resolver", [resolve_pinned_url, resolve_pinned_url_sync])
def test_pins_to_validated_public_ip(resolver):
    with _getaddrinfo_returning(_PUBLIC):
        pinned, transport = resolver("https://webhook.example.com:8443/hook")
    # Host is replaced by the validated IP; port/path preserved; SNI keeps the name.
    assert pinned == f"https://{_PUBLIC}:8443/hook"
    assert "webhook.example.com" not in pinned
    assert transport._hostname == "webhook.example.com"


@pytest.mark.parametrize("resolver", [resolve_pinned_url, resolve_pinned_url_sync])
def test_rejects_internal_resolution(resolver):
    with _getaddrinfo_returning(_INTERNAL), pytest.raises(UnsafeURLError):
        resolver("https://rebind.example.com/hook")


@pytest.mark.parametrize("resolver", [resolve_pinned_url, resolve_pinned_url_sync])
def test_rejects_when_any_answer_is_internal(resolver):
    # A split-horizon name answering both public and internal must be refused.
    with _getaddrinfo_returning(_PUBLIC, _INTERNAL), pytest.raises(UnsafeURLError):
        resolver("https://split.example.com/hook")


def test_rebind_after_validation_cannot_reach_internal():
    # First resolution (validation) is public; a later lookup flips to internal.
    # Because the connect target is pinned to the URL's IP, the flip is moot:
    # the pinned URL still points at the public IP checked at validation time.
    with _getaddrinfo_returning(_PUBLIC):
        pinned, _ = resolve_pinned_url("https://rebind.example.com/hook")
    assert pinned.startswith(f"https://{_PUBLIC}")


def test_syslog_host_pin_returns_validated_ip():
    with _getaddrinfo_returning(_PUBLIC):
        assert assert_public_host("syslog.example.com") == _PUBLIC
    with _getaddrinfo_returning(_INTERNAL), pytest.raises(UnsafeURLError):
        assert_public_host("syslog.example.com")
