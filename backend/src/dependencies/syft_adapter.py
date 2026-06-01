"""Syft adapter — sends a checkout to the dependencies scanner over HTTP.

Phase 7 moves Syft out of the backend container and behind a warm ``http_api``
mode in the scanner image. Two transports are supported:

- ``mount`` — the scanner has the workspace volume mounted; the adapter only
  forwards a ``workspace://<scan_id>/<repo>`` URI.
- ``minio`` (default) — the adapter packs the checkout into a gzipped tarball,
  uploads it to the ``aegis-checkouts`` bucket, and forwards the resulting
  object key.

The public ``run_syft`` signature is unchanged so existing engine callers
(``_try_incremental_dep_scan``) need no modification. Missing transport env
vars surface as ``AdapterUnavailableError`` so the incremental engine falls
through to the full-scan path transparently.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from src.shared.checkout_upload import (
    MinioCredentialsMissing,
    MinioOperationFailed,
    upload_checkout,
)
from src.shared.scanner_http_client import (
    AdapterFailedError,
    AdapterUnavailableError,
    ScannerHttpClient,
    checkout_path_to_workspace_uri,
    get_checkout_transport,
)

__all__ = ["run_syft", "AdapterUnavailableError", "AdapterFailedError"]

logger = logging.getLogger(__name__)

_SCANNER = "dependencies"


def _upload_for_dependencies(checkout_path: Path) -> str:
    """Wrap the shared uploader in adapter-specific exception semantics.

    The incremental engine treats AdapterUnavailableError as a signal to fall
    through to the full-scan path. Missing-credential failures map to
    AdapterUnavailableError; operational failures (bucket-ensure, put_object)
    map to AdapterFailedError so the engine surfaces the real error.
    """
    if not checkout_path.exists():
        raise AdapterFailedError(
            f"{_SCANNER}:syft",
            0,
            f"checkout path does not exist: {checkout_path}",
        )

    try:
        return upload_checkout(_SCANNER, checkout_path)
    except MinioCredentialsMissing as exc:
        raise AdapterUnavailableError(str(exc)) from exc
    except MinioOperationFailed as exc:
        raise AdapterFailedError(f"{_SCANNER}:syft", 0, str(exc)) from exc


def run_syft(checkout_path: Path) -> dict[str, Any]:
    """POST a checkout reference to the dependencies scanner and return the SBOM.

    Parameters
    ----------
    checkout_path:
        Root of the repository checkout to scan. Under ``mount`` transport
        this must be under ``/workspace``; under ``minio`` transport the path
        is read locally and uploaded as a tarball.

    Returns
    -------
    Parsed CycloneDX JSON dict.

    Raises
    ------
    AdapterUnavailableError
        When ``SCANNER_DEPS_URL`` is unset, the scanner is unreachable, or the
        configured transport's prerequisites are not met. The engine layer
        treats this as a signal to fall through to the full-scan path.
    AdapterFailedError
        When the scanner returns a non-503 4xx/5xx response or malformed JSON.
    """
    try:
        transport = get_checkout_transport()
    except ValueError as exc:
        raise AdapterUnavailableError(str(exc)) from exc

    if transport == "mount":
        try:
            uri = checkout_path_to_workspace_uri(checkout_path)
        except ValueError as exc:
            raise AdapterUnavailableError(str(exc)) from exc
        payload = {"checkout_ref": uri}
    else:
        key = _upload_for_dependencies(checkout_path)
        payload = {"checkout_minio_key": key}

    try:
        with ScannerHttpClient() as client:
            response = client.post_json("dependencies", "/v1/sbom", payload)
    except ValueError as exc:
        raise AdapterUnavailableError(str(exc)) from exc

    sbom = response.get("sbom")
    if not isinstance(sbom, dict):
        raise AdapterFailedError(
            "dependencies:/v1/sbom",
            200,
            f"expected 'sbom' dict in response, got {type(sbom).__name__}",
        )
    return sbom
