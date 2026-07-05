"""deps.dev client for a package version's upstream publish date.

Network I/O only ever touches the fixed deps.dev host below — the URL is built
from a compile-time constant plus URL-encoded package coordinates, never from
caller-supplied hosts. Used only by the opt-in release-age enrichment; an
air-gapped install never reaches this module because the enrichment is gated
off by default.

deps.dev covers six systems (NPM, PYPI, GO, MAVEN, CARGO, NUGET). The OSV
ecosystem string on a finding is mapped to one of these; anything else (distro
packages, RubyGems, Hex, …) has no deps.dev entry and is skipped.
"""
from __future__ import annotations

import logging
from datetime import date, datetime
from urllib.parse import quote

import httpx

logger = logging.getLogger(__name__)

DEPS_DEV_API_URL = "https://api.deps.dev"

# OSV ecosystem (lower-cased) → deps.dev system. Only these six are supported.
_OSV_TO_SYSTEM: dict[str, str] = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "golang": "go",
    "maven": "maven",
    "crates.io": "cargo",
    "cargo": "cargo",
    "crates": "cargo",
    "nuget": "nuget",
}


def system_for_ecosystem(ecosystem: str | None) -> str | None:
    """Map an OSV/purl ecosystem string to a deps.dev system, or None."""
    if not ecosystem:
        return None
    return _OSV_TO_SYSTEM.get(ecosystem.strip().lower())


def fetch_release_date(
    system: str, name: str, version: str, *, timeout: float = 10.0
) -> date | None:
    """Return the upstream publish date for one package version, or None.

    Returns None on any miss — unknown version, no publish date, transport
    error, or unexpected payload — so the caller degrades gracefully. Raising is
    reserved for nothing here: a freshness signal must never fail an ingest.
    """
    url = (
        f"{DEPS_DEV_API_URL}/v3/systems/{quote(system, safe='')}"
        f"/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}"
    )
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url)
        if resp.status_code != 200:
            return None
        published = resp.json().get("publishedAt")
    except (httpx.HTTPError, ValueError, TypeError) as exc:
        logger.debug("deps.dev lookup failed for %s/%s@%s: %s", system, name, version, exc)
        return None
    if not isinstance(published, str) or not published:
        return None
    try:
        # deps.dev returns RFC 3339, e.g. "2024-05-01T12:00:00Z".
        return datetime.fromisoformat(published.replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None
