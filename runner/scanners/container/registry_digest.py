"""SSRF-guarded registry HEAD digest fallback.

Port of the bash ``get_registry_digest`` / ``_validate_registry_host`` /
``_get_registry_auth_header`` block in scanners/container/run.sh.

When a CycloneDX SBOM lacks ``metadata.component.hashes`` SHA-256 (some
registries don't return it via syft), we fall back to a registry HEAD request
against the OCI distribution endpoint and parse the ``Docker-Content-Digest``
response header. The image's registry hostname is dynamically validated to
reject loopback, link-local, and RFC1918 private ranges before any network
request — mirrors the bash SSRF policy exactly.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import logging
import socket
import threading
from pathlib import Path
from typing import Iterable

from runner.scanners._subprocess import run_tool

logger = logging.getLogger(__name__)


_REGISTRY_HEAD_TIMEOUT_S = 30.0
_REGISTRY_TOKEN_TIMEOUT_S = 30.0

_OCI_MANIFEST_ACCEPT = (
    "application/vnd.oci.image.index.v1+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json, "
    "application/vnd.docker.distribution.manifest.v2+json"
)

# Hostnames explicitly blocked regardless of DNS resolution. Mirrors the bash
# ``case "$host" in localhost|*.localhost|metadata.google.internal|169.254.169.254)``
_BLOCKED_HOSTS_EXACT = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
}


class _ParsedRef:
    __slots__ = ("registry", "repo", "tag")

    def __init__(self, registry: str, repo: str, tag: str) -> None:
        self.registry = registry
        self.repo = repo
        self.tag = tag


def _parse_image_ref(image_ref: str) -> _ParsedRef | None:
    """Split ``registry/repo:tag`` into its three parts.

    Mirrors the bash ``_parse_image_ref``: only refs of the form
    ``<host>/<repo>:<tag>`` are parseable; bare names like ``alpine:3.18`` or
    digest-pinned refs return None (registry HEAD only makes sense with an
    explicit registry host)."""
    if "/" not in image_ref or ":" not in image_ref:
        return None
    no_tag, _, tag = image_ref.rpartition(":")
    if "/" not in no_tag:
        return None
    registry, _, repo = no_tag.partition("/")
    if not registry or not repo or not tag:
        return None
    return _ParsedRef(registry=registry, repo=repo, tag=tag)


def _is_blocked_host(host: str) -> bool:
    h = host.lower()
    if h in _BLOCKED_HOSTS_EXACT:
        return True
    if h.endswith(".localhost"):
        return True
    return False


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_link_local or ip.is_private:
        return True
    if ip.is_unspecified or ip.is_reserved or ip.is_multicast:
        return True
    return False


def _resolve_host(host: str) -> list[str]:
    """Return all A/AAAA records for ``host``. Empty list on failure."""
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


def _validate_registry_host(host: str) -> bool:
    """Return True if ``host`` is safe to contact.

    Blocks dangerous hostnames outright, then resolves the host and rejects
    any answer in the loopback / link-local / RFC1918 / multicast ranges.
    Mirrors the bash ``_validate_registry_host`` semantics; if DNS resolution
    fails, allows the call to proceed (the bash returns 0 in that path)."""
    if _is_blocked_host(host):
        logger.warning(
            "[!] SSRF blocked: registry hostname %r is not allowed", host
        )
        return False
    addrs = _resolve_host(host)
    if not addrs:
        # DNS failure — match bash behaviour and let curl surface the error.
        return True
    for addr in addrs:
        if _is_blocked_ip(addr):
            logger.warning(
                "[!] SSRF blocked: registry %r resolves to private IP %s",
                host,
                addr,
            )
            return False
    return True


def _read_docker_password(
    registry: str, config_path: Path | None = None
) -> str | None:
    """Look up ``auths[<registry>].password`` in ``~/.docker/config.json``.

    Returns None if the file is missing, malformed, or contains no entry for
    this registry. Mirrors the ``jq -r ".auths[\"$registry\"].password // empty"``
    in run.sh."""
    cfg = config_path or (Path.home() / ".docker" / "config.json")
    try:
        data = json.loads(cfg.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    entry = (data.get("auths") or {}).get(registry)
    if not isinstance(entry, dict):
        return None
    pw = entry.get("password")
    return pw if isinstance(pw, str) and pw else None


def _fetch_bearer_token(
    registry: str,
    repo: str,
    password: str,
    *,
    cancel_event: threading.Event | None,
) -> str | None:
    """Exchange the basic-auth password for a registry bearer token.

    Mirrors the curl + jq pipeline in ``_get_registry_auth_header``. Returns
    None on any failure (the caller falls back to basic auth)."""
    url = (
        f"https://{registry}/token"
        f"?scope=repository:{repo}:pull&service={registry}"
    )
    rc, stdout, _ = run_tool(
        [
            "curl",
            "-sf",
            "--max-time",
            str(int(_REGISTRY_TOKEN_TIMEOUT_S)),
            "-u",
            f"_token:{password}",
            url,
        ],
        timeout=_REGISTRY_TOKEN_TIMEOUT_S + 5,
        cancel_event=cancel_event,
    )
    if rc != 0 or not stdout:
        return None
    try:
        body = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    token = body.get("token")
    return token if isinstance(token, str) and token else None


def _auth_header(
    registry: str,
    repo: str,
    *,
    docker_config: Path | None,
    cancel_event: threading.Event | None,
) -> str | None:
    """Return a single ``Authorization: ...`` header for the registry, or None.

    Tries bearer-token exchange first; falls back to basic auth using the raw
    password from docker config (which OCI registries store base64-encoded as
    the password)."""
    password = _read_docker_password(registry, docker_config)
    if not password:
        return None
    bearer = _fetch_bearer_token(
        registry, repo, password, cancel_event=cancel_event
    )
    if bearer:
        return f"Authorization: Bearer {bearer}"
    basic = base64.b64encode(f"_token:{password}".encode()).decode()
    return f"Authorization: Basic {basic}"


def _parse_docker_content_digest(headers: str) -> str | None:
    """Extract the ``Docker-Content-Digest`` value from curl --head output.

    Tolerates mixed-case header names and CRLF endings — matches the bash
    pipeline ``grep -i ... | tr -d '\\r' | awk '{print $2}'``."""
    for raw_line in headers.splitlines():
        line = raw_line.rstrip("\r")
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() == "docker-content-digest":
            value = value.strip()
            return value or None
    return None


def fetch_registry_digest(
    image_ref: str,
    *,
    docker_config: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> str | None:
    """Return the OCI manifest digest for ``image_ref`` via HEAD, or None.

    Performs SSRF validation on the registry hostname, optionally adds an
    auth header from ``~/.docker/config.json``, and parses the
    ``Docker-Content-Digest`` response header from curl --head. None means
    "no digest available" — the caller decides whether that's a hard failure
    or a soft skip.
    """
    parsed = _parse_image_ref(image_ref)
    if parsed is None:
        return None
    if not _validate_registry_host(parsed.registry):
        return None

    auth = _auth_header(
        parsed.registry,
        parsed.repo,
        docker_config=docker_config,
        cancel_event=cancel_event,
    )

    cmd: list[str] = [
        "curl",
        "-sfI",
        "--max-time",
        str(int(_REGISTRY_HEAD_TIMEOUT_S)),
        "-H",
        f"Accept: {_OCI_MANIFEST_ACCEPT}",
    ]
    if auth:
        cmd.extend(["-H", auth])
    cmd.append(
        f"https://{parsed.registry}/v2/{parsed.repo}/manifests/{parsed.tag}"
    )

    rc, stdout, _ = run_tool(
        cmd,
        timeout=_REGISTRY_HEAD_TIMEOUT_S + 5,
        cancel_event=cancel_event,
    )
    if rc != 0 or not stdout:
        return None
    return _parse_docker_content_digest(stdout)


_MAX_TAGS = 500


def list_tags(
    image_ref: str,
    *,
    docker_config: Path | None = None,
    cancel_event: threading.Event | None = None,
) -> list[str] | None:
    """Return the registry tag list for ``image_ref``'s repo, or None.

    Same SSRF validation and pull-scoped auth as ``fetch_registry_digest`` —
    the ``/v2/<repo>/tags/list`` endpoint needs the identical token scope. The
    raw list is returned verbatim (capped); newer-version selection is the
    caller's job. None means "couldn't list" (unparseable ref, blocked host,
    transport error), which the caller treats as a soft skip.
    """
    parsed = _parse_image_ref(image_ref)
    if parsed is None:
        return None
    if not _validate_registry_host(parsed.registry):
        return None

    auth = _auth_header(
        parsed.registry,
        parsed.repo,
        docker_config=docker_config,
        cancel_event=cancel_event,
    )
    cmd: list[str] = ["curl", "-sf", "--max-time", str(int(_REGISTRY_HEAD_TIMEOUT_S))]
    if auth:
        cmd.extend(["-H", auth])
    cmd.append(f"https://{parsed.registry}/v2/{parsed.repo}/tags/list")

    rc, stdout, _ = run_tool(
        cmd,
        timeout=_REGISTRY_HEAD_TIMEOUT_S + 5,
        cancel_event=cancel_event,
    )
    if rc != 0 or not stdout:
        return None
    try:
        tags = json.loads(stdout).get("tags")
    except (ValueError, TypeError):
        return None
    if not isinstance(tags, list):
        return None
    return [t for t in tags if isinstance(t, str)][:_MAX_TAGS]


__all__: Iterable[str] = ("fetch_registry_digest", "list_tags")
