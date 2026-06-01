"""Grype adapter — sends a container-image SBOM to the scanner over HTTP.

Mirrors ``dependencies.grype_adapter`` but lives in the containers namespace
to keep the two call sites independently evolvable. The scanner-side
``http_api`` runs Grype in a warm process pool so each match request avoids
the per-job docker cold start.
"""
from __future__ import annotations

from typing import Any

from src.shared.scanner_http_client import (
    AdapterFailedError,
    AdapterUnavailableError,
    ScannerHttpClient,
)

__all__ = ["run_grype", "AdapterUnavailableError", "AdapterFailedError"]


def run_grype(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    """POST sbom to the container scanner and return a list of match dicts.

    Parameters
    ----------
    sbom:
        CycloneDX SBOM dict as produced by ``run_syft``.

    Returns
    -------
    List of Grype match dicts (the scanner unwraps ``grype -o json`` matches).

    Raises
    ------
    AdapterUnavailableError
        When ``SCANNER_CONTAINER_URL`` is unset or the scanner is unreachable.
    AdapterFailedError
        When the scanner returns a non-503 4xx/5xx response or malformed JSON.
    """
    try:
        with ScannerHttpClient() as client:
            response = client.post_json("container", "/v1/match", {"sbom": sbom})
    except ValueError as exc:
        raise AdapterUnavailableError(str(exc)) from exc

    matches = response.get("matches")
    if not isinstance(matches, list):
        raise AdapterFailedError(
            "container:/v1/match",
            200,
            f"expected 'matches' list in response, got {type(matches).__name__}",
        )
    return matches
