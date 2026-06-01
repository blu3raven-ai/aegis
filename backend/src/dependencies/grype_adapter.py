"""Grype adapter — sends a CycloneDX SBOM to the dependencies scanner over HTTP.

Phase 7 moved Grype out of the backend container and behind a warm
``http_api`` mode in the scanner image. This adapter posts the SBOM to
``POST /v1/match`` on ``SCANNER_DEPS_URL`` and returns the matches list.

The public ``run_grype`` signature is unchanged so existing engine callers
(``_try_incremental_dep_scan``) need no modification. When ``SCANNER_DEPS_URL``
is unset the adapter raises ``AdapterUnavailableError`` and the engine falls
through to the full-scan path transparently.

Grype-exit-1-is-success semantics are handled scanner-side in ``http_api.py``,
so this layer just unwraps ``response["matches"]``.
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
    """POST sbom to the dependencies scanner and return a list of match dicts.

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
        When ``SCANNER_DEPS_URL`` is unset or the scanner is unreachable. The
        engine layer treats this as a signal to fall through to the full-scan
        path.
    AdapterFailedError
        When the scanner returns a non-503 4xx/5xx response or malformed JSON.
    """
    try:
        with ScannerHttpClient() as client:
            response = client.post_json("dependencies", "/v1/match", {"sbom": sbom})
    except ValueError as exc:
        raise AdapterUnavailableError(str(exc)) from exc

    matches = response.get("matches")
    if not isinstance(matches, list):
        raise AdapterFailedError(
            "dependencies:/v1/match",
            200,
            f"expected 'matches' list in response, got {type(matches).__name__}",
        )
    return matches
