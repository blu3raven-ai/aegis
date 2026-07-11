"""Existence check for a self-hosted git repo URL, hardened against SSRF.

The major hosts (github/gitlab/bitbucket) are validated client-side; this covers
everything else, which needs a server-side request. Because the URL is
user-supplied, the check must not become an SSRF primitive: it is https-only,
refuses hosts that resolve to internal/reserved IP space, never follows
redirects, and never sends credentials. It probes the git smart-HTTP endpoint
(`/info/refs?service=git-upload-pack`) rather than cloning.

Residual: DNS between the resolve-time block and httpx's own resolution is a
rebinding TOCTOU window. The endpoint is admin-gated (MANAGE_SOURCES) and only
returns a boolean, which bounds the impact; pin-to-IP is the follow-up if this
is ever exposed more broadly.
"""
from __future__ import annotations

import ipaddress
import socket

import httpx

from src.sources.store import SourceValidationError

_TIMEOUT_S = 8.0


def _reject_internal(host: str, port: int) -> None:
    """Raise if *host* resolves to any non-public address (SSRF guard)."""
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return  # unresolvable — handled as "does not exist" by the caller
    for *_rest, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise SourceValidationError(
                "That host resolves to an internal address and can't be validated."
            )


async def repo_url_exists(url: str) -> bool:
    """True if a public git repo is reachable at *url* over https.

    Raises SourceValidationError for a non-https URL or an internal host.
    """
    from urllib.parse import urlparse

    parsed = urlparse((url or "").strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise SourceValidationError("Only https:// repository URLs can be validated.")

    _reject_internal(parsed.hostname, parsed.port or 443)

    probe = url.strip().rstrip("/") + "/info/refs?service=git-upload-pack"
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_S, follow_redirects=False) as client:
            res = await client.get(probe, headers={"User-Agent": "git/2.0 (aegis-validate)"})
    except httpx.HTTPError:
        return False  # unreachable / TLS error → treat as not found, never blocking

    # Smart-HTTP servers advertise refs with this content type for a real repo.
    return res.status_code == 200 and "git-upload-pack" in res.headers.get("content-type", "")
