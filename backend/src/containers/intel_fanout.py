"""Intel fan-out: re-match all cached container SBOMs when a new CVE is published.

Mirrors src.dependencies.intel_fanout for the container scanner namespace.
Phase 3/4 wires the trigger; Phase 2b ships the function so it is ready as
soon as Argus/NVD push events arrive.

Runs sequentially across cached SBOMs; future optimisation can parallelise
when the SBOM count warrants it.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Callable

from src.dependencies.sbom_cache import ContainerSbomCache
from src.shared.event_emit_helpers import emit_finding_created

logger = logging.getLogger(__name__)

_SOURCE_COMPONENT = "containers.intel_fanout"


# ── SBOM package matching helpers (shared logic, mirrored from deps fanout) ──

def _parse_version_tuple(v: str) -> tuple[int, ...]:
    """Convert a dotted-numeric version string to a comparable tuple.

    Non-numeric segments are stripped so '2.17.2-SNAPSHOT' compares as (2, 17, 2).
    Returns an empty tuple on complete parse failure.
    """
    parts = []
    for segment in v.strip().split("."):
        numeric = re.match(r"^(\d+)", segment)
        if numeric:
            parts.append(int(numeric.group(1)))
    return tuple(parts)


def _version_in_range(version_str: str, version_range: str) -> bool:
    """Check whether version_str satisfies version_range (e.g. '<2.17.2').

    Supports single-operator ranges: <, <=, >, >=, ==, !=.
    Returns True on any parse failure to err on the side of re-matching.
    """
    if not version_range or not version_str:
        return True

    bound = version_range.strip()
    op = ""
    for prefix in ("<=", ">=", "!=", "<", ">", "=="):
        if bound.startswith(prefix):
            op = prefix
            bound = bound[len(prefix):].strip()
            break

    if not op:
        return True

    v = _parse_version_tuple(version_str)
    t = _parse_version_tuple(bound)

    if not v or not t:
        return True

    if op == "<":
        return v < t
    if op == "<=":
        return v <= t
    if op == ">":
        return v > t
    if op == ">=":
        return v >= t
    if op == "==":
        return v == t
    if op == "!=":
        return v != t
    return True


def _sbom_contains_affected(
    sbom: dict[str, Any],
    affected_packages: list[dict[str, Any]],
) -> bool:
    """Return True if the SBOM contains any component matching affected_packages.

    Checks both CycloneDX ('components') and Syft Packages ('artifacts')
    schemas to be tolerant of SBOM format variations.
    """
    for pkg in affected_packages:
        name = pkg.get("name", "")
        version_range = pkg.get("version_range", "")
        for comp in sbom.get("components", []) + sbom.get("artifacts", []):
            comp_name = comp.get("name", "")
            comp_ver = comp.get("version", "")
            if comp_name.lower() == name.lower():
                if _version_in_range(comp_ver, version_range):
                    return True
    return False


# ── Main fan-out function ──────────────────────────────────────────────────────

def dispatch_intel_fanout(
    cve_id: str,
    affected_packages: list[dict[str, Any]],
    sbom_cache: ContainerSbomCache,
    grype_runner: Callable[[dict[str, Any]], list[dict[str, Any]]],
) -> int:
    """Re-match every cached container SBOM containing an affected package@version range.

    Returns count of SBOMs re-matched (i.e. SBOMs that were actually checked
    by Grype, not just iterated).

    Each new finding produced emits finding.created via the Phase 0 helper.
    """
    entries = sbom_cache.list_entries()

    matched = 0
    for entry in entries:
        # For container SBOMs the cache_key IS the image digest
        image_digest = entry.cache_key

        sbom = sbom_cache.download_blob_by_entry(entry)
        if sbom is None:
            logger.warning(
                "blob missing for image_digest=%s; skipping", image_digest
            )
            continue

        if not _sbom_contains_affected(sbom, affected_packages):
            continue

        matched += 1
        try:
            findings = grype_runner(sbom)
        except Exception:
            logger.exception(
                "grype_runner failed for image_digest=%s cve=%s; continuing fan-out",
                image_digest,
                cve_id,
            )
            continue

        for finding in findings:
            emit_finding_created(
                org_id=finding.get("org_id", ""),
                finding=finding,
                scanner_type="containers",
                source_component=_SOURCE_COMPONENT,
            )

    logger.info(
        "containers.intel_fanout cve=%s: %d/%d cached SBOMs re-matched",
        cve_id,
        matched,
        len(entries),
    )
    return matched
