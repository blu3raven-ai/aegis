"""Cache-aware dependency scan engine.

Phase 2a ships the engine logic and cache integration.
Live Syft/Grype subprocess wiring is deferred to the Phase 1b warm-pool
follow-up when Syft runs inside the scanner container.

Callers inject syft_runner and grype_runner so tests can mock them without
subprocesses and production can swap in real runners when Phase 1b lands.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from src.dependencies.manifest_hash import compute_manifest_set_hash
from src.dependencies.sbom_cache import SbomCache


@dataclass
class ScanResult:
    findings: list[dict[str, Any]]
    cached: bool
    manifest_set_hash: str
    duration_ms: int


class DepsBaselineDelta:
    """Incremental dependency scanner: reuses cached SBOM when manifests unchanged."""

    def __init__(
        self,
        sbom_cache: SbomCache,
        syft_runner: Callable[[Path], dict[str, Any]],
        grype_runner: Callable[[dict[str, Any]], list[dict[str, Any]]],
    ) -> None:
        self._cache = sbom_cache
        self._syft = syft_runner
        self._grype = grype_runner

    def scan(self, repo_id: str, checkout_path: Path) -> ScanResult:
        """Run a cache-aware dependency scan.

        Cache hit  → skip Syft, pass cached SBOM to Grype directly.
        Cache miss → run Syft to produce a fresh SBOM, cache it, run Grype.

        Grype errors propagate to the caller; the cache is only written on
        successful Grype completion so a partial result is never cached.
        """
        t0 = time.monotonic()
        manifest_hash = compute_manifest_set_hash(checkout_path)

        sbom = self._cache.get(repo_id, manifest_hash)
        if sbom is not None:
            findings = self._grype(sbom)
            return ScanResult(
                findings=findings,
                cached=True,
                manifest_set_hash=manifest_hash,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        # Cache miss — generate fresh SBOM then store it
        sbom = self._syft(checkout_path)

        # Grype runs before cache write so a Grype failure doesn't pollute the cache
        findings = self._grype(sbom)

        # syft_runner is responsible for embedding its own version metadata;
        # use the bomFormat field if present, otherwise fall back to a sentinel
        tool_version = (
            sbom.get("metadata", {}).get("toolVersion")
            or sbom.get("tool_version")
            or "syft-unknown"
        )
        self._cache.put(repo_id, manifest_hash, sbom, tool_version)

        return ScanResult(
            findings=findings,
            cached=False,
            manifest_set_hash=manifest_hash,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
