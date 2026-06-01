"""HTTP client helper for talking to the warm scanner containers (Phase 7).

The backend traditionally invokes scanner binaries (syft, grype, opengrep,
trufflehog) directly via subprocess. Phase 7 introduces an HTTP transport so
the same binaries can be served from long-running containers instead, removing
per-job cold-start cost.

This module is plumbing only — no adapter currently imports it. Step 3 of the
plan will swap the per-scanner adapters over.

Design points
-------------
- URL resolution is per-scanner via env vars: ``SCANNER_DEPS_URL``,
  ``SCANNER_CONTAINER_URL``, ``SCANNER_SAST_URL``, ``SCANNER_SECRETS_URL``.
  Missing env raises ``ValueError`` so misconfiguration fails loudly at boot
  rather than during a scan.
- Checkout transport: ``CHECKOUT_TRANSPORT`` env selects how the scanner
  receives the repository checkout. ``minio`` (default) uploads a tarball to
  the shared object store; ``mount`` relies on the scanner container having
  the workspace volume mounted and sends a ``workspace://`` URI.
- Errors are translated into the same typed exceptions used by the subprocess
  adapters so callers can swap transports without changing exception handling:
  ``AdapterUnavailableError`` for connect failures / 503 (transient), and
  ``AdapterFailedError`` for other HTTP errors and malformed payloads.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Final, Literal

import httpx

from src.shared.subprocess_runner import (
    AdapterFailedError,
    AdapterUnavailableError,
)

__all__ = [
    "AdapterFailedError",
    "AdapterUnavailableError",
    "CHECKOUT_TRANSPORT_ENV",
    "ScannerHttpClient",
    "checkout_path_to_workspace_uri",
    "get_checkout_transport",
    "resolve_base_url",
]


# ─── Env var contract ───────────────────────────────────────────────────────

_SCANNER_URL_ENV: Final[dict[str, str]] = {
    "dependencies": "SCANNER_DEPS_URL",
    "container": "SCANNER_CONTAINER_URL",
    "sast": "SCANNER_SAST_URL",
    "secrets": "SCANNER_SECRETS_URL",
}

CHECKOUT_TRANSPORT_ENV: Final[str] = "CHECKOUT_TRANSPORT"

CheckoutTransport = Literal["minio", "mount"]
_VALID_TRANSPORTS: Final[tuple[str, ...]] = ("minio", "mount")
_DEFAULT_TRANSPORT: Final[str] = "minio"

_WORKSPACE_ROOT: Final[Path] = Path("/workspace")


# ─── URL resolution ─────────────────────────────────────────────────────────


def resolve_base_url(scanner_type: str) -> str:
    """Look up the base URL for a scanner container.

    Raises
    ------
    ValueError
        If ``scanner_type`` is unknown or the env var is unset/empty.
    """
    try:
        env_var = _SCANNER_URL_ENV[scanner_type]
    except KeyError as exc:
        raise ValueError(
            f"unknown scanner type {scanner_type!r}; "
            f"expected one of {sorted(_SCANNER_URL_ENV)}"
        ) from exc

    url = os.environ.get(env_var, "").strip()
    if not url:
        raise ValueError(
            f"{env_var} is not set — scanner HTTP transport requires this env var"
        )
    return url.rstrip("/")


def get_checkout_transport() -> CheckoutTransport:
    """Return the configured checkout transport (``minio`` or ``mount``)."""
    value = os.environ.get(CHECKOUT_TRANSPORT_ENV, _DEFAULT_TRANSPORT).strip().lower()
    if value not in _VALID_TRANSPORTS:
        raise ValueError(
            f"{CHECKOUT_TRANSPORT_ENV}={value!r} invalid; "
            f"expected one of {_VALID_TRANSPORTS}"
        )
    return value  # type: ignore[return-value]


# ─── Path → URI translation ─────────────────────────────────────────────────


def checkout_path_to_workspace_uri(checkout_path: Path) -> str:
    """Translate a backend-visible checkout path into a ``workspace://`` URI.

    The backend mounts the same volume as the scanner container at
    ``/workspace``. The URI form is what the scanner expects in the
    HTTP request body, decoupling the wire protocol from any specific local
    mount layout.

    Raises
    ------
    ValueError
        If the path is not under ``/workspace`` or contains traversal segments
        that would escape that directory.
    """
    resolved = Path(os.path.normpath(str(checkout_path)))
    try:
        rel = resolved.relative_to(_WORKSPACE_ROOT)
    except ValueError as exc:
        raise ValueError(
            f"checkout path {checkout_path!s} must be under /workspace/"
        ) from exc

    parts = rel.parts
    if not parts:
        raise ValueError(
            f"checkout path {checkout_path!s} must include scan_id and repo segments"
        )

    return "workspace://" + "/".join(parts)


# ─── HTTP client ────────────────────────────────────────────────────────────


class ScannerHttpClient:
    """Synchronous JSON-over-HTTP client for the scanner containers.

    A single long-lived ``httpx.Client`` is held for the lifetime of the
    instance so successive requests reuse the underlying TCP/TLS connection
    pool — building a fresh client per call would re-pay the handshake on
    every scan and defeat the warm-pool premise.

    ``transport`` is exposed so unit tests can inject ``httpx.MockTransport``;
    production callers leave it ``None`` and a real connection is used.

    Supports the context-manager protocol; in long-running services prefer
    ``with ScannerHttpClient() as c:`` so the underlying socket pool is
    closed deterministically on shutdown.
    """

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        default_timeout: float = 600.0,
    ) -> None:
        self._default_timeout = default_timeout

        client_kwargs: dict[str, Any] = {"timeout": default_timeout}
        if transport is not None:
            client_kwargs["transport"] = transport
        self._client = httpx.Client(**client_kwargs)

    def close(self) -> None:
        """Close the underlying httpx.Client and its connection pool."""
        self._client.close()

    def __enter__(self) -> "ScannerHttpClient":
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()

    def post_json(
        self,
        scanner: str,
        path: str,
        payload: dict[str, Any],
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """POST ``payload`` as JSON to ``<base>/path`` and return parsed JSON.

        Raises
        ------
        ValueError
            On missing env var for the scanner.
        AdapterUnavailableError
            On connection failure or HTTP 503 (caller may fall back).
        AdapterFailedError
            On any other 4xx/5xx response or malformed JSON in the body.
        """
        base_url = resolve_base_url(scanner)
        url = f"{base_url}{path}"
        effective_timeout = timeout if timeout is not None else self._default_timeout

        try:
            response = self._client.post(url, json=payload, timeout=effective_timeout)
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout) as exc:
            raise AdapterUnavailableError(
                f"scanner {scanner!r} unreachable at {url}: {exc}"
            ) from exc

        if response.status_code == 503:
            raise AdapterUnavailableError(
                f"scanner {scanner!r} returned 503 at {url}: {response.text[:200]}"
            )
        if response.status_code >= 400:
            raise AdapterFailedError(
                f"{scanner}:{path}",
                response.status_code,
                response.text,
            )

        try:
            return response.json()
        except (json.JSONDecodeError, ValueError) as exc:
            raise AdapterFailedError(
                f"{scanner}:{path}",
                response.status_code,
                f"malformed json response: {exc}",
            ) from exc
