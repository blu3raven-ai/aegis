"""Download the Argus threat-intelligence DB for grype matching.

Port of the ``download_argus_db`` shell function in
scanners/dependencies/run.sh. When both ``ARGUS_API_KEY`` and
``ARGUS_ENDPOINT`` are set, attempts to fetch ``<endpoint>/api/db/latest``
via curl with a Bearer token and writes the response body to a file in
``work_dir``. The returned path is later passed to grype via ``--db``.

Failure handling is intentionally permissive: any error (missing creds,
unsafe endpoint, HTTP failure, empty body) returns ``None`` so the caller
can fall back to the next-priority DB (vunnel-built custom DB, then
Grype's built-in DB). Mirrors the bash original which prints a warning
and proceeds without aborting the scan.

SSRF guard: the endpoint URL is validated before any network call. HTTPS
is required, embedded credentials are rejected, and the hostname is
resolved against the same private-range deny-list used by the container
scanner's registry HEAD path.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import threading
from pathlib import Path
from urllib.parse import urlsplit

from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)


_ARGUS_DOWNLOAD_TIMEOUT_S = 120.0
_ARGUS_PATH_SUFFIX = "/api/db/latest"
_ARGUS_DB_FILENAME = "argus.db"

# Hostnames explicitly blocked regardless of DNS resolution. Mirrors the
# container scanner's SSRF deny-list so an attacker who controls the Argus
# config cannot pivot to cloud metadata endpoints.
_BLOCKED_HOSTS_EXACT = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "169.254.169.254",
    }
)


class _EndpointValidationError(ValueError):
    """Internal: raised when ARGUS_ENDPOINT fails SSRF validation."""


def _validate_endpoint(endpoint: str) -> str:
    """Return the trimmed endpoint, raising on any SSRF policy violation."""
    if not endpoint:
        raise _EndpointValidationError("ARGUS_ENDPOINT is empty")
    cleaned = endpoint.strip().rstrip("/")
    parts = urlsplit(cleaned)
    if parts.scheme.lower() != "https":
        raise _EndpointValidationError(
            f"ARGUS_ENDPOINT must use https:// (got scheme {parts.scheme!r})"
        )
    if "@" in parts.netloc:
        raise _EndpointValidationError(
            "ARGUS_ENDPOINT must not embed user-info"
        )
    host = parts.hostname
    if not host:
        raise _EndpointValidationError("ARGUS_ENDPOINT is missing a hostname")
    if host.lower() in _BLOCKED_HOSTS_EXACT or host.lower().endswith(".localhost"):
        raise _EndpointValidationError(
            f"ARGUS_ENDPOINT hostname {host!r} is not allowed"
        )
    for addr in _resolve_host(host):
        if _is_blocked_ip(addr):
            raise _EndpointValidationError(
                f"ARGUS_ENDPOINT {host!r} resolves to private IP {addr}"
            )
    return cleaned


def _resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, OSError):
        return []
    addrs: list[str] = []
    for entry in infos:
        sockaddr = entry[4]
        if sockaddr and isinstance(sockaddr[0], str):
            addrs.append(sockaddr[0])
    return addrs


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return (
        ip.is_loopback
        or ip.is_link_local
        or ip.is_private
        or ip.is_unspecified
        or ip.is_reserved
        or ip.is_multicast
    )


def download_argus_db(
    work_dir: Path | str,
    *,
    cancel_event: threading.Event | None = None,
) -> Path | None:
    """Download the Argus threat-intel DB to ``work_dir``.

    Returns the path to the downloaded ``.db`` file, or ``None`` if creds
    are missing, the endpoint fails SSRF validation, the HTTP request
    fails, or the response body is empty. Never raises — the caller falls
    through to the next-priority advisory DB on ``None``.
    """
    import os  # local import keeps the module test-clean (env mutations)

    api_key = os.environ.get("ARGUS_API_KEY", "").strip()
    endpoint = os.environ.get("ARGUS_ENDPOINT", "").strip()
    if not api_key or not endpoint:
        return None

    try:
        endpoint = _validate_endpoint(endpoint)
    except _EndpointValidationError as e:
        logger.warning("[!] Argus DB download skipped: %s", e)
        return None

    work_path = Path(work_dir)
    try:
        work_path.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        logger.warning("[!] Argus DB work dir unavailable: %s", e)
        return None

    db_path = work_path / _ARGUS_DB_FILENAME
    url = f"{endpoint}{_ARGUS_PATH_SUFFIX}"
    logger.info("[+] Downloading Argus threat intelligence DB...")

    rc, _, stderr = run_tool(
        [
            "curl",
            "-fsSL",
            "--max-time",
            str(int(_ARGUS_DOWNLOAD_TIMEOUT_S)),
            "-H",
            f"Authorization: Bearer {api_key}",
            "-o",
            str(db_path),
            url,
        ],
        timeout=_ARGUS_DOWNLOAD_TIMEOUT_S + 5,
        cancel_event=cancel_event,
    )
    if rc != 0:
        logger.warning(
            "[!] Argus DB download failed (curl rc=%d): %s — using next DB",
            rc,
            (stderr or "")[:200],
        )
        _safe_unlink(db_path)
        return None

    if not db_path.exists() or db_path.stat().st_size == 0:
        logger.warning(
            "[!] Argus DB download returned empty body — using next DB"
        )
        _safe_unlink(db_path)
        return None

    logger.info("[✓] Argus DB downloaded: %s", db_path)
    return db_path


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


__all__ = ("download_argus_db",)
