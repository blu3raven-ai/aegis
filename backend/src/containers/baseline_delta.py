"""Cache-aware container image scan engine.

Phase 2b ships the engine logic and container SBOM cache integration.
Live Syft/Grype subprocess wiring is deferred to Phase 1b when the scanner
container is warm.

Callers inject syft_runner and grype_runner so tests can mock them without
subprocesses and production can swap in real runners when Phase 1b lands.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from src.dependencies.sbom_cache import ContainerSbomCache


@dataclass
class ContainerScanResult:
    findings: list[dict[str, Any]]
    cached: bool
    image_digest: str
    duration_ms: int


class ContainerBaselineDelta:
    """Incremental container image scanner: reuses cached SBOM when digest unchanged.

    Container image digests are content-addressed and immutable, making them a
    perfect cache key — if the digest matches a stored SBOM, no re-pull or
    Syft invocation is needed.
    """

    def __init__(
        self,
        sbom_cache: ContainerSbomCache,
        syft_runner: Callable[[str], dict[str, Any]],
        grype_runner: Callable[[dict[str, Any]], list[dict[str, Any]]],
    ) -> None:
        self._cache = sbom_cache
        self._syft = syft_runner
        self._grype = grype_runner

    def scan(self, image_digest: str, image_pull_ref: str) -> ContainerScanResult:
        """Run a cache-aware container image scan.

        Cache hit  → skip Syft, pass cached SBOM to Grype directly.
        Cache miss → call syft_runner(image_pull_ref) to produce a fresh SBOM,
                     cache it, then run Grype.

        Grype errors propagate to the caller; the cache is only written on
        successful Grype completion so a partial result is never cached.
        """
        t0 = time.monotonic()

        sbom = self._cache.get_by_digest(image_digest)
        if sbom is not None:
            findings = self._grype(sbom)
            return ContainerScanResult(
                findings=findings,
                cached=True,
                image_digest=image_digest,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )

        # Cache miss — generate fresh SBOM from the pull ref, then store it
        sbom = self._syft(image_pull_ref)

        # Grype runs before cache write so a Grype failure doesn't pollute the cache
        findings = self._grype(sbom)

        # syft_runner embeds its own version metadata; fall back to a sentinel if absent
        tool_version = (
            sbom.get("metadata", {}).get("toolVersion")
            or sbom.get("tool_version")
            or "syft-unknown"
        )
        self._cache.put_by_digest(image_digest, sbom, tool_version)

        return ContainerScanResult(
            findings=findings,
            cached=False,
            image_digest=image_digest,
            duration_ms=int((time.monotonic() - t0) * 1000),
        )
