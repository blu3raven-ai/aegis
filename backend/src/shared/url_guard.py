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
from urllib.parse import urlsplit

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Cloud metadata service addresses — global-looking but must never be reached.
_METADATA_ADDRESSES = frozenset({"169.254.169.254", "fd00:ec2::254"})


class UnsafeURLError(ValueError):
    """Raised when a destination URL is not permitted for outbound delivery."""


def _is_disallowed_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if str(addr) in _METADATA_ADDRESSES:
        return True
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_private
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def assert_sendable_url(url: str) -> None:
    """Raise UnsafeURLError unless `url` is a public http(s) endpoint.

    Every address the host resolves to must be a global/public IP; a single
    internal answer rejects the whole URL so a split-horizon name can't slip
    through.
    """
    parts = urlsplit(url)
    if parts.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f"scheme not permitted: {parts.scheme!r}")

    host = parts.hostname
    if not host:
        raise UnsafeURLError("missing host")

    try:
        infos = socket.getaddrinfo(host, parts.port or None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeURLError(f"host does not resolve: {host}") from exc

    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise UnsafeURLError(f"host does not resolve: {host}")

    for ip in resolved:
        if _is_disallowed_ip(ip):
            raise UnsafeURLError("destination resolves to a non-public address")
