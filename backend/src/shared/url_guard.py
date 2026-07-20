"""SSRF guard for admin/tenant-configured outbound URLs.

Several settings surfaces let an admin supply an arbitrary URL that the server
then fetches (notification destinations, SAML metadata, BYO-LLM and Argus
connection endpoints). Without validation that URL can point at the loopback
interface, an RFC1918 host, or the cloud metadata endpoint — turning an
outbound request into a server-side request forgery primitive. The guard here
rejects any URL whose scheme is not http(s) or that resolves to a non-global
address.

Resolution happens here, at call time, rather than trusting the hostname
literally: it closes the obvious "http://127.0.0.1" case and shrinks the
DNS-rebinding window to the gap between this check and httpx's own connect.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata service addresses — global-looking but must never be reached.
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})


class UnsafeURLError(ValueError):
    """Raised when a destination URL is not permitted for outbound delivery."""


_CGNAT_RANGE = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 — shared carrier-grade NAT


def _is_disallowed_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if str(addr) in _METADATA_ADDRESSES:
        return True
    # RFC 6598 CGNAT space isn't flagged as private by stdlib ipaddress, but is
    # non-routable and can host internal/metadata services in some clouds.
    if addr.version == 4 and addr in _CGNAT_RANGE:
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def _resolve_public_ip(host: str, port: int | None = None) -> str:
    """Resolve `host`, reject if ANY address is non-public, return the first IP.

    Rejecting on any single internal answer stops a split-horizon name from
    slipping through. The returned IP lets callers *pin* the connection to the
    address that was validated, closing the DNS-rebinding window between check
    and connect.
    """
    try:
        infos = socket.getaddrinfo(host, port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"host does not resolve: {host}") from exc

    resolved = [info[4][0] for info in infos]
    if not resolved:
        raise UnsafeURLError(f"host does not resolve: {host}")

    for ip in resolved:
        if _is_disallowed_ip(ip):
            raise UnsafeURLError("destination resolves to a non-public address")
    return resolved[0]


def assert_sendable_url(url: str) -> None:
    """Raise UnsafeURLError unless `url` is a public http(s) endpoint."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme not permitted: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("missing host")
    _resolve_public_ip(host, parts.port)


def assert_public_host(host: str) -> str:
    """Validate a bare host (no scheme) and return the validated IP to connect to.

    For raw-socket sinks (e.g. syslog TCP) that can't carry a URL scheme:
    connect to the returned IP, not the hostname, so the connection can't be
    rebound to an internal address after validation.
    """
    if not host:
        raise UnsafeURLError("missing host")
    return _resolve_public_ip(host)


class _HostPinningTransport(httpx.AsyncHTTPTransport):
    """Async httpx transport that restores the original hostname for TLS SNI.

    Pairs with :func:`resolve_pinned_url`: the request URL carries the validated
    IP so the connect can't be rebound, while SNI + certificate verification
    still use the real hostname.
    """

    def __init__(self, hostname: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        request.extensions["sni_hostname"] = self._hostname.encode("ascii")
        return await super().handle_async_request(request)


class _SyncHostPinningTransport(httpx.HTTPTransport):
    """Sync counterpart of :class:`_HostPinningTransport`."""

    def __init__(self, hostname: str, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._hostname = hostname

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        request.extensions["sni_hostname"] = self._hostname.encode("ascii")
        return super().handle_request(request)


def _pin(url: str) -> tuple[str, str]:
    """Validate `url` and return (ip_pinned_url, original_hostname). Raises UnsafeURLError."""
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme not permitted: {parts.scheme!r}")
    host = parts.hostname
    if not host:
        raise UnsafeURLError("missing host")
    ip = _resolve_public_ip(host, parts.port)
    ip_host = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
    netloc = f"{ip_host}:{parts.port}" if parts.port else ip_host
    pinned = urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    return pinned, host


def resolve_pinned_url(url: str) -> tuple[str, _HostPinningTransport]:
    """Validate `url`; return an IP-pinned URL plus an SNI-preserving async transport.

    The returned URL has its host replaced by the validated IP, so httpx
    connects to the address that was checked rather than whatever a second DNS
    lookup returns (DNS-rebinding defense). Use both together:

        pinned, transport = resolve_pinned_url(url)
        async with httpx.AsyncClient(transport=transport) as c:
            await c.post(pinned, ...)

    Raises UnsafeURLError.
    """
    pinned, host = _pin(url)
    return pinned, _HostPinningTransport(host)


def resolve_pinned_url_sync(url: str) -> tuple[str, _SyncHostPinningTransport]:
    """Sync counterpart of :func:`resolve_pinned_url` for ``httpx.Client``."""
    pinned, host = _pin(url)
    return pinned, _SyncHostPinningTransport(host)
