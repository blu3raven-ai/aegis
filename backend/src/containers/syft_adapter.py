"""Syft adapter — sends a container image reference to the scanner over HTTP.

Phase 7 moved Syft out of the backend container and behind a warm ``http_api``
mode in the container scanner image. This adapter posts the image ref to
``POST /v1/sbom`` on ``SCANNER_CONTAINER_URL`` and returns the CycloneDX SBOM.

Unlike the dependencies adapter there is no checkout transport — container
scans operate on a registry reference, so the request payload is just the
image pull ref.

The public ``run_syft`` signature is unchanged so existing engine callers
(``_try_incremental_container_scan``) need no modification. Missing env vars
surface as ``AdapterUnavailableError`` so the engine falls through to the
full-scan path transparently.
"""
from __future__ import annotations

from typing import Any

from src.shared.scanner_http_client import (
    AdapterFailedError,
    AdapterUnavailableError,
    ScannerHttpClient,
)

__all__ = ["run_syft", "AdapterUnavailableError", "AdapterFailedError"]


def run_syft(image_pull_ref: str) -> dict[str, Any]:
    """POST image_pull_ref to the container scanner and return a CycloneDX SBOM.

    Parameters
    ----------
    image_pull_ref:
        Full image reference, e.g. ``docker.io/library/nginx:1.27``.

    Returns
    -------
    Parsed CycloneDX JSON dict.

    Raises
    ------
    AdapterUnavailableError
        When ``SCANNER_CONTAINER_URL`` is unset or the scanner is unreachable.
    AdapterFailedError
        When the scanner returns a non-503 4xx/5xx response or malformed JSON.
    """
    try:
        with ScannerHttpClient() as client:
            response = client.post_json(
                "container", "/v1/sbom", {"image_pull_ref": image_pull_ref}
            )
    except ValueError as exc:
        raise AdapterUnavailableError(str(exc)) from exc

    sbom = response.get("sbom")
    if not isinstance(sbom, dict):
        raise AdapterFailedError(
            "container:/v1/sbom",
            200,
            f"expected 'sbom' dict in response, got {type(sbom).__name__}",
        )
    return sbom
