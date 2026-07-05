"""Opengrep adapter — sends an HTTP scan request to the warm SAST scanner.

Phase 7 swap: the backend no longer shells out to a local ``opengrep`` binary.
The warm scanner container exposes ``POST /v1/scan`` (see
``scanners/code-scanning/http_api.py``); this adapter is the client side.

Checkout transport is controlled by ``CHECKOUT_TRANSPORT``:

- ``minio`` (default): the backend tars the checkout up, uploads to MinIO,
  and passes the object key. Suitable when backend and scanner do not share
  a filesystem (the default Phase 7 topology).
- ``mount``: backend and scanner both mount the same workspace volume at
  ``/workspace``; we translate the local path to a ``workspace://`` URI and
  pass that. Lower latency, no tarball overhead.

Public API
----------
``run_opengrep(checkout_path, files=None)`` is preserved verbatim from the
subprocess-era contract so existing callers in ``src/code_scanning/scanner.py``
need ZERO changes. The ``files`` list (when supplied) is forwarded to the
scanner so it can narrow opengrep to just the changed files.
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

__all__ = ["run_opengrep", "AdapterUnavailableError", "AdapterFailedError"]

_SCANNER = "sast"


def run_opengrep(
    checkout_path: Path,
    files: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Run opengrep on ``checkout_path`` and return SAST findings.

    Parameters
    ----------
    checkout_path:
        Root of the repository checkout to scan.
    files:
        Optional list of file paths relative to ``checkout_path`` to restrict
        the scan. The incremental engine supplies its per-file change list
        here so unchanged files do not re-pay opengrep's parse cost.

    Returns
    -------
    Opengrep ``results`` array (parsed from the scanner's JSON response).

    Raises
    ------
    AdapterUnavailableError
        When the scanner container is unreachable or returns 503.
    AdapterFailedError
        When the scanner returns any other 4xx/5xx or a malformed body.
    """
    transport = get_checkout_transport()
    payload: dict[str, Any] = {}
    if files:
        payload["files"] = list(files)

    if transport == "mount":
        payload["checkout_ref"] = checkout_path_to_workspace_uri(checkout_path)
    else:
        payload["checkout_minio_key"] = upload_checkout(_SCANNER, checkout_path)

    with ScannerHttpClient() as client:
        body = client.post_json(_SCANNER, "/v1/scan", payload)

    results = body.get("results", [])
    if not isinstance(results, list):
        raise AdapterFailedError(_SCANNER, 200, "scanner returned non-list 'results'")

    logger.info("opengrep scan returned %d result(s)", len(results))
    return results
