"""TruffleHog adapter — sends an HTTP scan request to the warm secrets scanner.

Phase 7 swap: the backend no longer shells out to a local ``trufflehog`` binary.
The warm scanner container exposes ``POST /v1/scan`` (see
``scanners/secrets/http_api.py``); this adapter is the client side.

Checkout transport is controlled by ``CHECKOUT_TRANSPORT``:

- ``minio`` (default): the backend has the checkout on a local mount; we tar
  it up, upload to MinIO, and pass the object key. Suitable when backend and
  scanner do not share a filesystem (the default Phase 7 topology).
- ``mount``: backend and scanner both mount the same workspace volume at
  ``/workspace``; we translate the local path to a ``workspace://`` URI and
  pass that. Lower latency, no tarball overhead.

Public API
----------
``run_trufflehog(checkout_path, commit_sha)`` is preserved verbatim from the
subprocess-era contract so existing callers in ``src/secrets/scanner.py``
need ZERO changes.

Security
--------
This adapter NEVER logs the response body (finding ``Raw`` fields are raw
secrets). Only the count is logged.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.shared.checkout_upload import upload_checkout
from src.shared.scanner_http_client import (
    AdapterFailedError,
    AdapterUnavailableError,
    ScannerHttpClient,
    checkout_path_to_workspace_uri,
    get_checkout_transport,
)

logger = logging.getLogger(__name__)

__all__ = ["run_trufflehog", "AdapterUnavailableError", "AdapterFailedError"]

_SCANNER = "secrets"


def run_trufflehog(checkout_path: Path, commit_sha: str) -> list[dict[str, Any]]:
    """Scan from ``commit_sha`` forward in ``checkout_path``.

    Routes the request to the warm secrets scanner over HTTP. The wire-level
    transport for the checkout itself is picked by ``CHECKOUT_TRANSPORT``.

    Returns
    -------
    List of TruffleHog finding dicts (parsed NDJSON output from the scanner).

    Raises
    ------
    AdapterUnavailableError
        When the scanner container is unreachable or returns 503.
    AdapterFailedError
        When the scanner returns any other 4xx/5xx or a malformed body.
    """
    transport = get_checkout_transport()
    payload: dict[str, Any] = {"since_commit": commit_sha}

    if transport == "mount":
        payload["checkout_ref"] = checkout_path_to_workspace_uri(checkout_path)
    else:
        payload["checkout_minio_key"] = upload_checkout(_SCANNER, checkout_path)

    with ScannerHttpClient() as client:
        body = client.post_json(_SCANNER, "/v1/scan", payload)

    findings = body.get("findings", [])
    if not isinstance(findings, list):
        raise AdapterFailedError(_SCANNER, 200, "scanner returned non-list 'findings'")

    # SECURITY: never log the response body — TruffleHog findings carry the
    # raw secret in the ``Raw`` field. Counts only.
    logger.info("trufflehog scan returned %d finding(s)", len(findings))
    return findings
