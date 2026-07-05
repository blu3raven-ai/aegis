"""CISA KEV catalog fetcher.

Fetches the JSON feed from cisa.gov, normalises each entry to our internal
field names, and returns a list ready for upsert.  Network I/O only ever
touches cisa.gov — no third-party intel proxies.
"""
from __future__ import annotations

import logging
from datetime import date
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


def _parse_date(raw: str | None) -> date | None:
    """Parse YYYY-MM-DD strings from the CISA feed; return None on any failure."""
    if not raw:
        return None
    try:
        return date.fromisoformat(raw.strip())
    except (ValueError, AttributeError):
        return None


def _parse_ransomware(raw: str | None) -> bool | None:
    """The upstream field is 'Known' | 'Unknown' | '' — map to bool | None."""
    if raw is None:
        return None
    normalised = raw.strip().lower()
    if normalised == "known":
        return True
    if normalised == "unknown":
        return False
    return None


def _normalise_entry(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map one upstream JSON object to our internal field names.

    Returns None when the row has no cveID, which is the one field we cannot
    synthesise and need as a PK.
    """
    cve_id = raw.get("cveID") or raw.get("cve_id")
    if not cve_id:
        return None
    return {
        "cve_id": cve_id.strip(),
        "vendor_project": raw.get("vendorProject") or raw.get("vendor_project"),
        "product": raw.get("product"),
        "vulnerability_name": raw.get("vulnerabilityName") or raw.get("vulnerability_name"),
        "date_added": _parse_date(raw.get("dateAdded") or raw.get("date_added")),
        "short_description": raw.get("shortDescription") or raw.get("short_description"),
        "required_action": raw.get("requiredAction") or raw.get("required_action"),
        "due_date": _parse_date(raw.get("dueDate") or raw.get("due_date")),
        "known_ransomware_use": _parse_ransomware(
            raw.get("knownRansomwareCampaignUse") or raw.get("known_ransomware_use")
        ),
        "notes": raw.get("notes"),
        "cwes": raw.get("cwes") or [],
    }


def fetch_kev_catalog(timeout: float = 30.0) -> list[dict[str, Any]]:
    """Fetch and parse the CISA KEV catalog from the official JSON feed.

    Returns a list of normalised entry dicts ready for KevService.upsert_catalog.
    Raises httpx.HTTPError on network failures so callers can decide on retry
    strategy without swallowing transport errors silently.

    Individual rows that cannot be parsed are skipped with a WARNING log so a
    single malformed entry never aborts the full refresh.
    """
    with httpx.Client(timeout=timeout) as client:
        resp = client.get(CISA_KEV_JSON_URL)
        resp.raise_for_status()

    payload = resp.json()

    # The feed wraps entries under a 'vulnerabilities' key.
    raw_entries: list[dict] = payload.get("vulnerabilities", [])
    if not isinstance(raw_entries, list):
        raise ValueError(
            f"Unexpected CISA KEV feed shape: 'vulnerabilities' is {type(raw_entries).__name__}"
        )

    entries: list[dict[str, Any]] = []
    for i, raw in enumerate(raw_entries):
        try:
            entry = _normalise_entry(raw)
            if entry is None:
                logger.warning("KEV row %d has no cveID — skipping: %r", i, raw)
                continue
            entries.append(entry)
        except Exception:
            logger.warning("Failed to parse KEV row %d — skipping: %r", i, raw, exc_info=True)

    logger.info("Fetched %d KEV entries from CISA", len(entries))
    return entries
