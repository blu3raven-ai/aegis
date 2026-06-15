"""Fetch long-form advisory text from NVD + OSV.dev at normalize time."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx

logger = logging.getLogger(__name__)


_CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_OSV_URL = "https://api.osv.dev/v1/vulns"


@dataclasses.dataclass(frozen=True)
class AdvisoryDetail:
    """Rich advisory text + metadata, sourced from NVD and/or OSV."""

    advisory_id: str
    summary: str = ""
    description: str = ""
    references: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    vulnerable_version_range: str = ""
    published_at: str = ""
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "advisoryId": self.advisory_id,
            "summary": self.summary,
            "description": self.description,
            "references": list(self.references),
            "cwes": list(self.cwes),
            "vulnerableVersionRange": self.vulnerable_version_range,
            "publishedAt": self.published_at,
            "sources": list(self.sources),
        }


def default_cache_dir() -> Path:
    """Persistent cache shared across scans on the same host."""
    return Path(
        os.environ.get("AEGIS_ADVISORY_CACHE_DIR")
        or Path.home() / ".cache" / "aegis" / "advisory"
    )


def fetch_advisory_details(
    advisory_ids: list[str],
    *,
    cache_dir: Path | None = None,
    nvd_api_key: str | None = None,
    cache_ttl_seconds: int = _CACHE_TTL_SECONDS,
    http_client: httpx.Client | None = None,
) -> dict[str, AdvisoryDetail]:
    """Cache-first fetch from NVD + OSV, keyed by advisory id."""
    unique_ids = sorted({i for i in advisory_ids if _looks_like_advisory_id(i)})
    if not unique_ids:
        return {}

    cache = _AdvisoryCache(cache_dir or default_cache_dir(), ttl_seconds=cache_ttl_seconds)

    results: dict[str, AdvisoryDetail] = {}
    to_fetch: list[str] = []
    for aid in unique_ids:
        cached = cache.get(aid)
        if cached is not None:
            results[aid] = cached
        else:
            to_fetch.append(aid)

    if not to_fetch:
        return results

    owns_client = http_client is None
    client = http_client or httpx.Client(timeout=15.0)
    try:
        for aid in to_fetch:
            detail = _fetch_one(aid, client=client, nvd_api_key=nvd_api_key)
            if detail is not None:
                cache.put(aid, detail)
                results[aid] = detail
    finally:
        if owns_client:
            client.close()

    return results


def _looks_like_advisory_id(value: str) -> bool:
    return bool(value) and (_CVE_RE.match(value) or _GHSA_RE.match(value))


def _fetch_one(
    advisory_id: str,
    *,
    client: httpx.Client,
    nvd_api_key: str | None,
) -> AdvisoryDetail | None:
    nvd: AdvisoryDetail | None = None
    if _CVE_RE.match(advisory_id):
        nvd = _fetch_nvd(advisory_id, client=client, api_key=nvd_api_key)

    osv = _fetch_osv(advisory_id, client=client)

    if nvd is None and osv is None:
        return None
    if nvd is None:
        return osv
    if osv is None:
        return nvd
    return _merge(nvd, osv)


def _fetch_nvd(
    cve_id: str,
    *,
    client: httpx.Client,
    api_key: str | None,
) -> AdvisoryDetail | None:
    headers = {"apiKey": api_key} if api_key else {}
    try:
        resp = client.get(_NVD_URL, params={"cveId": cve_id}, headers=headers)
    except httpx.HTTPError as exc:
        logger.debug("NVD fetch failed for %s: %s", cve_id, exc)
        return None
    if resp.status_code == 429:
        # Back off and skip; cache will retry next scan
        time.sleep(2)
        return None
    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}

    descriptions = cve.get("descriptions") or []
    description = next(
        (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
    )
    refs = tuple(
        r.get("url", "") for r in (cve.get("references") or []) if r.get("url")
    )
    cwes: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            cwe_id = desc.get("value", "")
            if cwe_id and cwe_id not in ("NVD-CWE-noinfo", "NVD-CWE-Other"):
                cwes.append(cwe_id)

    vuln_range = _nvd_version_range(cve.get("configurations") or [])

    return AdvisoryDetail(
        advisory_id=cve_id,
        summary=_truncate(description, 280),
        description=description,
        references=refs,
        cwes=tuple(dict.fromkeys(cwes)),
        vulnerable_version_range=vuln_range,
        published_at=cve.get("published", ""),
        sources=("nvd",),
    )


def _fetch_osv(
    advisory_id: str,
    *,
    client: httpx.Client,
) -> AdvisoryDetail | None:
    try:
        resp = client.get(f"{_OSV_URL}/{advisory_id}")
    except httpx.HTTPError as exc:
        logger.debug("OSV fetch failed for %s: %s", advisory_id, exc)
        return None
    if resp.status_code == 429:
        time.sleep(1)
        return None
    if resp.status_code == 404:
        return None
    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    summary = data.get("summary", "")
    description = data.get("details", "")
    refs = tuple(
        r.get("url", "")
        for r in (data.get("references") or [])
        if r.get("url")
    )

    cwes: list[str] = []
    for db_specific in (data.get("database_specific") or {}).get("cwe_ids") or []:
        if isinstance(db_specific, str) and db_specific.startswith("CWE-"):
            cwes.append(db_specific)
    # Some OSV entries put CWE under affected[].database_specific
    for affected in data.get("affected") or []:
        cwe_ids = (affected.get("database_specific") or {}).get("cwe_ids") or []
        for cid in cwe_ids:
            if isinstance(cid, str) and cid.startswith("CWE-"):
                cwes.append(cid)

    vuln_range = _osv_version_range(data.get("affected") or [])

    return AdvisoryDetail(
        advisory_id=advisory_id,
        summary=summary or _truncate(description, 280),
        description=description,
        references=refs,
        cwes=tuple(dict.fromkeys(cwes)),
        vulnerable_version_range=vuln_range,
        published_at=data.get("published", ""),
        sources=("osv",),
    )


def _merge(left: AdvisoryDetail, right: AdvisoryDetail) -> AdvisoryDetail:
    """Combine two advisory details. Longer description wins; refs/cwes unioned."""

    def longer(a: str, b: str) -> str:
        return a if len(a) >= len(b) else b

    refs_merged = tuple(dict.fromkeys((*left.references, *right.references)))
    cwes_merged = tuple(dict.fromkeys((*left.cwes, *right.cwes)))
    return AdvisoryDetail(
        advisory_id=left.advisory_id,
        summary=longer(left.summary, right.summary),
        description=longer(left.description, right.description),
        references=refs_merged,
        cwes=cwes_merged,
        vulnerable_version_range=left.vulnerable_version_range or right.vulnerable_version_range,
        published_at=left.published_at or right.published_at,
        sources=tuple(dict.fromkeys((*left.sources, *right.sources))),
    )


def _nvd_version_range(configurations: list[dict]) -> str:
    for cfg in configurations:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                end_excl = match.get("versionEndExcluding")
                end_incl = match.get("versionEndIncluding")
                start_incl = match.get("versionStartIncluding")
                if end_excl:
                    return (
                        f">= {start_incl}, < {end_excl}"
                        if start_incl
                        else f"< {end_excl}"
                    )
                if end_incl:
                    return (
                        f">= {start_incl}, <= {end_incl}"
                        if start_incl
                        else f"<= {end_incl}"
                    )
    return ""


def _osv_version_range(affected: list[dict]) -> str:
    for entry in affected:
        for r in entry.get("ranges") or []:
            events = r.get("events") or []
            introduced = next(
                (e.get("introduced") for e in events if "introduced" in e), None
            )
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            last_affected = next(
                (e.get("last_affected") for e in events if "last_affected" in e), None
            )
            if fixed:
                return (
                    f">= {introduced}, < {fixed}"
                    if introduced and introduced != "0"
                    else f"< {fixed}"
                )
            if last_affected:
                return (
                    f">= {introduced}, <= {last_affected}"
                    if introduced and introduced != "0"
                    else f"<= {last_affected}"
                )
    return ""


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


class _AdvisoryCache:
    """Tiny file-per-advisory JSON cache. Survives process restarts."""

    def __init__(self, root: Path, *, ttl_seconds: int) -> None:
        self._root = root
        self._ttl = ttl_seconds
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.debug("Cache dir unavailable (%s): %s", self._root, exc)
            self._root = None  # type: ignore[assignment]

    def _path(self, advisory_id: str) -> Path:
        digest = hashlib.sha1(advisory_id.encode()).hexdigest()
        return self._root / f"{digest}.json"

    def get(self, advisory_id: str) -> AdvisoryDetail | None:
        if self._root is None:
            return None
        p = self._path(advisory_id)
        if not p.exists():
            return None
        try:
            age = time.time() - p.stat().st_mtime
            if age > self._ttl:
                return None
            data = json.loads(p.read_text())
        except (OSError, ValueError):
            return None
        try:
            return AdvisoryDetail(
                advisory_id=data["advisoryId"],
                summary=data.get("summary", ""),
                description=data.get("description", ""),
                references=tuple(data.get("references") or ()),
                cwes=tuple(data.get("cwes") or ()),
                vulnerable_version_range=data.get("vulnerableVersionRange", ""),
                published_at=data.get("publishedAt", ""),
                sources=tuple(data.get("sources") or ()),
            )
        except (KeyError, TypeError):
            return None

    def put(self, advisory_id: str, detail: AdvisoryDetail) -> None:
        if self._root is None:
            return
        p = self._path(advisory_id)
        try:
            p.write_text(json.dumps(detail.to_dict(), separators=(",", ":")))
        except OSError as exc:
            logger.debug("Cache write failed for %s: %s", advisory_id, exc)
