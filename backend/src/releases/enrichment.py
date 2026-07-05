"""Release-age enrichment — stamp each finding with its installed version's age.

Opt-in and gated off by default. For findings on deps.dev-supported ecosystems,
resolve the installed version's upstream publish date (cache-first, deps.dev on
miss) and stamp ``release_age_days`` — days between publish and this scan — onto
the raw finding. A very small value is a supply-chain freshness signal
(compromised releases are often caught within days) and is exposed as a
rules-engine predicate. Ecosystems deps.dev doesn't cover are left untouched.
"""
from __future__ import annotations

import logging
from datetime import date

from src.releases.fetcher import fetch_release_date, system_for_ecosystem
from src.releases.service import PackageReleaseDateService

logger = logging.getLogger(__name__)


def _coord(finding: dict) -> tuple[str, str, str] | None:
    dep = finding.get("dependency") or {}
    pkg = dep.get("package") or {}
    system = system_for_ecosystem(pkg.get("ecosystem"))
    name = pkg.get("name")
    version = finding.get("current_version")
    if system and name and version:
        return (system, str(name), str(version))
    return None


def enrich_findings_with_release_age(
    findings: list[dict],
    *,
    today: date,
    threshold_days: int,
    service: PackageReleaseDateService | None = None,
) -> list[dict]:
    """Stamp ``release_age_days`` (and ``release_recent``) onto findings.

    ``today`` is injected so the age is deterministic and testable.
    ``release_recent`` is True when the installed version was published within
    ``threshold_days`` of the scan — the display/warning signal. Findings on
    unsupported ecosystems, or versions deps.dev has no date for, are returned
    unchanged. All network/DB failures degrade to "no stamp" — this must never
    fail an ingest.
    """
    if not findings:
        return findings
    svc = service or PackageReleaseDateService()

    coords = {c for f in findings if (c := _coord(f))}
    if not coords:
        return findings

    cached = svc.get_cached(coords)
    to_fetch = [c for c in coords if c not in cached]

    fresh: dict[tuple[str, str, str], date | None] = {}
    for system, name, version in to_fetch:
        fresh[(system, name, version)] = fetch_release_date(system, name, version)
    if fresh:
        svc.upsert([
            {"system": s, "name": n, "version": v, "published_at": pub}
            for (s, n, v), pub in fresh.items()
        ])

    resolved = {**cached, **fresh}
    for finding in findings:
        coord = _coord(finding)
        if coord is None:
            continue
        published = resolved.get(coord)
        if published is not None:
            age = max(0, (today - published).days)
            finding["release_age_days"] = age
            finding["release_recent"] = age < threshold_days
    return findings


def maybe_enrich_release_age(
    findings: list[dict], config: dict, org: str
) -> list[dict]:
    """Gate: run release-age enrichment only when the opt-in setting is on.

    ``config`` is a scanner config dict (``releaseAgeEnabled`` / threshold). Any
    failure is swallowed with a warning so a freshness lookup never fails ingest.
    """
    if config.get("releaseAgeEnabled") not in (True, "true"):
        return findings
    try:
        threshold = int(config.get("releaseAgeThresholdDays") or 90)
    except (TypeError, ValueError):
        threshold = 90
    try:
        from datetime import date as _date

        return enrich_findings_with_release_age(
            findings, today=_date.today(), threshold_days=threshold
        )
    except Exception:
        logger.warning("Release-age enrichment failed for %s", org)
        return findings
