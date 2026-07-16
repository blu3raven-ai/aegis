"""SSRF guard for user-supplied instance URLs (_validate_instance_url).

The guard resolves the hostname and rejects any private/internal address, then
pins the validated IP into the returned URL so the caller connects to the address
we checked — not whatever the next DNS lookup returns (DNS-rebinding defense).
These assert every internal range is blocked and the pinning behavior is correct.
"""
from __future__ import annotations

import socket
from unittest.mock import patch

import httpx
import pytest

from src.sources.test_connection import (
    ConnectionTestError,
    _parse_github_total,
    _validate_instance_url,
)


def _resolves_to(*ips):
    """Fake socket.getaddrinfo returning the given IPs as A/AAAA records."""
    def fake(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]
    return patch("src.sources.test_connection.socket.getaddrinfo", side_effect=fake)


@pytest.mark.parametrize("bad_ip", [
    "10.0.0.5",        # private
    "192.168.1.1",     # private
    "172.16.0.1",      # private
    "127.0.0.1",       # loopback
    "169.254.169.254", # link-local — the cloud metadata endpoint, the classic SSRF target
    "0.0.0.0",         # unspecified
    "224.0.0.1",       # multicast
])
def test_rejects_internal_addresses(bad_ip):
    with _resolves_to(bad_ip):
        with pytest.raises(ConnectionTestError, match="private/internal"):
            _validate_instance_url("https://evil.example.com")


def test_rejects_internal_even_when_a_public_address_is_also_returned():
    # A hostname resolving to both a public and a private IP must be rejected —
    # the guard checks every returned address, not just the first.
    with _resolves_to("93.184.216.34", "10.0.0.1"):
        with pytest.raises(ConnectionTestError, match="private/internal"):
            _validate_instance_url("https://mixed.example.com")


def test_rejects_non_http_scheme():
    with pytest.raises(ConnectionTestError, match="scheme"):
        _validate_instance_url("ftp://example.com")


def test_rejects_missing_hostname():
    with pytest.raises(ConnectionTestError, match="missing hostname"):
        _validate_instance_url("https://")


def test_unresolvable_hostname_errors():
    with patch("src.sources.test_connection.socket.getaddrinfo", side_effect=socket.gaierror):
        with pytest.raises(ConnectionTestError, match="Cannot resolve"):
            _validate_instance_url("https://nope.invalid")


def test_empty_resolution_errors():
    # getaddrinfo returns no addresses (not a gaierror) → still cannot connect.
    with _resolves_to():
        with pytest.raises(ConnectionTestError, match="Cannot resolve"):
            _validate_instance_url("https://empty.example.com")


def test_public_address_is_pinned_into_the_url():
    with _resolves_to("93.184.216.34"):
        out = _validate_instance_url("https://example.com/api/v3/")
    # hostname replaced with the validated IP, path kept, trailing slash stripped
    assert out == "https://93.184.216.34/api/v3"


def test_port_is_preserved_when_pinning():
    with _resolves_to("93.184.216.34"):
        out = _validate_instance_url("https://example.com:8443/base")
    assert out == "https://93.184.216.34:8443/base"


def test_ipv6_public_address_is_bracketed():
    with _resolves_to("2606:2800:220:1:248:1893:25c8:1946"):
        out = _validate_instance_url("https://example.com")
    assert out == "https://[2606:2800:220:1:248:1893:25c8:1946]"


# --- pagination parser ---

def test_parse_github_total_uses_last_page_link():
    resp = httpx.Response(200, headers={"Link": '<https://api/x?page=7>; rel="last"'})
    assert _parse_github_total(resp) == 7 * 30


def test_parse_github_total_ignores_malformed_page_and_falls_back():
    # A non-numeric page= in the last link must not crash — fall back to body count.
    resp = httpx.Response(200, headers={"Link": '<https://api/x?page=abc>; rel="last"'}, json=[{"a": 1}])
    assert _parse_github_total(resp) == 1


def test_parse_github_total_falls_back_to_array_length():
    resp = httpx.Response(200, json=[{"a": 1}, {"b": 2}, {"c": 3}])
    assert _parse_github_total(resp) == 3


def test_parse_github_total_zero_when_unparseable():
    resp = httpx.Response(200, text="not a json array")
    assert _parse_github_total(resp) == 0
