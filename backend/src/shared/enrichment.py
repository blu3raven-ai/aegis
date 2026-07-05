"""Shared advisory enrichment — NVD NIST and GitHub Advisory Database lookups.

Used by both the Dependency Scanning and Container Scanning modules to enrich
vulnerability findings with publication dates, CVSS scores, and advisory URLs.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_JSONL_SIZE_MB = 200
MAX_JSONL_LINES = 1_000_000


def ingest_findings_jsonl(
    org: str,
    run_id: str,
    findings_path: Path,
) -> list[dict[str, Any]]:
    """Read canonical findings.jsonl emitted by the runner."""
    if not findings_path.exists():
        logger.warning("[!] No findings.jsonl found at %s", findings_path)
        return []

    stats = findings_path.stat()
    max_bytes = MAX_JSONL_SIZE_MB * 1024 * 1024
    if stats.st_size > max_bytes:
        raise ValueError(
            f"findings.jsonl too large ({round(stats.st_size / 1024 / 1024)}MB > {MAX_JSONL_SIZE_MB}MB limit)"
        )

    lines = findings_path.read_text(encoding="utf-8").splitlines()
    if len(lines) > MAX_JSONL_LINES:
        raise ValueError(f"Too many lines ({len(lines)} > {MAX_JSONL_LINES} limit)")

    findings: list[dict[str, Any]] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            finding = json.loads(stripped)
            if isinstance(finding, dict):
                findings.append(finding)
        except json.JSONDecodeError:
            logger.warning("[!] Skipping malformed JSONL line in %s", findings_path)
    return findings


def _fetch_nvd_metadata(cve_ids: list[str], api_key: str = "") -> dict[str, dict[str, Any]]:
    """Fetch CVE metadata from NIST NVD API."""
    import httpx
    import time as _time

    metadata: dict[str, dict[str, Any]] = {}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    # With API key: 50 req/30s → sleep 1s every 4. Without: 5 req/30s → sleep 7s every 4.
    throttle_sleep = 1 if api_key else 7
    with httpx.Client(timeout=15.0, headers=headers) as client:
        for i, cve_id in enumerate(cve_ids):
            if not cve_id.startswith("CVE-"):
                continue
            if i > 0 and i % 4 == 0:
                _time.sleep(throttle_sleep)
            try:
                response = client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cveId": cve_id},
                )
                if response.status_code == 200:
                    data = response.json()
                    vulns = data.get("vulnerabilities", [])
                    if vulns:
                        cve_data = vulns[0].get("cve", {})
                        published = cve_data.get("published", "")
                        modified = cve_data.get("lastModified", "")
                        metrics = cve_data.get("metrics", {})
                        cvss_v31 = metrics.get("cvssMetricV31", [])
                        cvss_score = None
                        cvss_vector = None
                        if cvss_v31:
                            cvss_data = cvss_v31[0].get("cvssData", {})
                            cvss_score = cvss_data.get("baseScore")
                            cvss_vector = cvss_data.get("vectorString")
                        if not cvss_score:
                            cvss_v30 = metrics.get("cvssMetricV30", [])
                            if cvss_v30:
                                cvss_data = cvss_v30[0].get("cvssData", {})
                                cvss_score = cvss_data.get("baseScore")
                                cvss_vector = cvss_data.get("vectorString")
                        descriptions = cve_data.get("descriptions", [])
                        description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
                        # Extract references
                        refs = [{"url": r.get("url", "")} for r in cve_data.get("references", []) if r.get("url")]
                        # Extract CWEs
                        cwes: list[dict[str, str]] = []
                        for weakness in cve_data.get("weaknesses", []):
                            for desc in weakness.get("description", []):
                                cwe_id = desc.get("value", "")
                                if cwe_id and cwe_id != "NVD-CWE-noinfo" and cwe_id != "NVD-CWE-Other":
                                    cwes.append({"cwe_id": cwe_id, "name": ""})
                        # Extract affected version range from configurations
                        vuln_range = ""
                        configs = cve_data.get("configurations", [])
                        if configs:
                            nodes = configs[0].get("nodes", [])
                            if nodes:
                                for match in nodes[0].get("cpeMatch", []):
                                    end_excl = match.get("versionEndExcluding")
                                    end_incl = match.get("versionEndIncluding")
                                    start_incl = match.get("versionStartIncluding")
                                    if end_excl:
                                        vuln_range = f">= {start_incl}, < {end_excl}" if start_incl else f"< {end_excl}"
                                    elif end_incl:
                                        vuln_range = f">= {start_incl}, <= {end_incl}" if start_incl else f"<= {end_incl}"
                                    if vuln_range:
                                        break

                        metadata[cve_id] = {
                            "published_at": published,
                            "updated_at": modified,
                            "cvss_score": cvss_score,
                            "cvss_vector": cvss_vector,
                            "summary": description,
                            "description": description,
                            "html_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "references": refs,
                            "vulnerable_version_range": vuln_range,
                            "first_patched_version": None,
                            "cwes": cwes,
                        }
            except Exception:
                logger.debug("NVD lookup failed for %s", cve_id)
                continue
    return metadata


def _fetch_github_advisory_metadata(advisory_ids: list[str], token: str) -> dict[str, dict[str, Any]]:
    """Fetch advisory metadata from GitHub Advisory Database."""
    import httpx

    metadata: dict[str, dict[str, Any]] = {}
    if not token or not advisory_ids:
        return metadata

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    import re
    _GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
    _CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

    with httpx.Client(timeout=10.0) as client:
        for advisory_id in advisory_ids:
            if not (_GHSA_RE.match(advisory_id) or _CVE_RE.match(advisory_id)):
                continue
            try:
                response = client.get(
                    f"https://api.github.com/advisories/{advisory_id}",
                    headers=headers,
                )
                if response.status_code == 200:
                    data = response.json()
                    refs = [{"url": r} for r in (data.get("references") or []) if isinstance(r, str) and r]
                    vulns = data.get("vulnerabilities") or []
                    vuln_range = ""
                    patched_version = None
                    if vulns:
                        vuln_range = vulns[0].get("vulnerable_version_range", "")
                        pv = vulns[0].get("first_patched_version")
                        if pv:
                            patched_version = pv if isinstance(pv, str) else pv
                    cwes = [{"cwe_id": c.get("cwe_id", ""), "name": c.get("name", "")} for c in (data.get("cwes") or [])]
                    metadata[advisory_id] = {
                        "published_at": data.get("published_at", ""),
                        "updated_at": data.get("updated_at", ""),
                        "cvss_score": (data.get("cvss", {}) or {}).get("score"),
                        "cvss_vector": (data.get("cvss", {}) or {}).get("vector_string"),
                        "summary": data.get("summary", ""),
                        "description": data.get("description", ""),
                        "html_url": data.get("html_url", ""),
                        "references": refs,
                        "vulnerable_version_range": vuln_range,
                        "first_patched_version": patched_version,
                        "cwes": cwes,
                    }
                    for alias in data.get("identifiers", []):
                        alias_val = alias.get("value", "")
                        if alias_val and alias_val != advisory_id:
                            metadata[alias_val] = metadata[advisory_id]
            except Exception:
                logger.debug("GitHub advisory lookup failed for %s", advisory_id)
                continue
    return metadata


def _merge_metadata(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    """Merge two metadata dicts — overlay fills in blanks, longer descriptions win."""
    merged = dict(base)
    for key, val in overlay.items():
        existing = merged.get(key)
        if key == "description":
            # Longer description wins (GitHub Advisory usually has richer markdown)
            if isinstance(val, str) and len(val) > len(existing or ""):
                merged[key] = val
        elif key == "references":
            # Merge reference lists, deduplicate by URL
            existing_urls = {r.get("url") for r in (existing or []) if r.get("url")}
            combined = list(existing or [])
            for ref in (val or []):
                if ref.get("url") and ref["url"] not in existing_urls:
                    combined.append(ref)
                    existing_urls.add(ref["url"])
            merged[key] = combined
        elif key == "cwes":
            # Merge CWE lists, deduplicate by cwe_id; prefer entries with names
            by_id: dict[str, dict[str, str]] = {}
            for cwe in (existing or []):
                by_id[cwe.get("cwe_id", "")] = cwe
            for cwe in (val or []):
                cid = cwe.get("cwe_id", "")
                if cid not in by_id or (cwe.get("name") and not by_id[cid].get("name")):
                    by_id[cid] = cwe
            merged[key] = list(by_id.values())
        elif not existing and val:
            merged[key] = val
    return merged


def _fetch_advisory_metadata(
    advisory_ids: list[str],
    *,
    nvd_enabled: bool = True,
    nvd_api_key: str = "",
    ghsa_enabled: bool = True,
    ghsa_api_key: str = "",
) -> dict[str, dict[str, Any]]:
    """Fetch from NVD and/or GitHub Advisory, merge best data from each."""
    unique_ids = list(set(advisory_ids))
    metadata: dict[str, dict[str, Any]] = {}

    # 1. NVD
    if nvd_enabled:
        cve_ids = [aid for aid in unique_ids if aid.startswith("CVE-")]
        if cve_ids:
            try:
                metadata.update(_fetch_nvd_metadata(cve_ids, api_key=nvd_api_key))
            except Exception:
                logger.debug("NVD batch lookup failed")

    # 2. GitHub Advisory DB
    if ghsa_enabled and ghsa_api_key:
        try:
            gh_metadata = _fetch_github_advisory_metadata(unique_ids, ghsa_api_key)
            for aid, gh_meta in gh_metadata.items():
                if aid in metadata:
                    metadata[aid] = _merge_metadata(metadata[aid], gh_meta)
                else:
                    metadata[aid] = gh_meta
        except Exception:
            logger.debug("GitHub Advisory batch lookup failed")
    elif ghsa_enabled and not ghsa_api_key:
        logger.info("[+] GHSA enrichment enabled but no API key configured — skipping")

    return metadata


def enrich_findings_with_advisory_data(
    findings: list[dict[str, Any]],
    *,
    nvd_enabled: bool = True,
    nvd_api_key: str = "",
    ghsa_enabled: bool = True,
    ghsa_api_key: str = "",
) -> list[dict[str, Any]]:
    """Enrich findings with publication dates, CVSS scores, and URLs from advisory databases."""
    advisory_ids: list[str] = []
    for finding in findings:
        advisory = finding.get("security_advisory") or {}
        ghsa_id = advisory.get("ghsa_id", "")
        cve_id = advisory.get("cve_id", "")
        if ghsa_id:
            advisory_ids.append(ghsa_id)
        if cve_id:
            advisory_ids.append(cve_id)

    if not advisory_ids:
        return findings

    metadata = _fetch_advisory_metadata(
        advisory_ids,
        nvd_enabled=nvd_enabled,
        nvd_api_key=nvd_api_key,
        ghsa_enabled=ghsa_enabled,
        ghsa_api_key=ghsa_api_key,
    )
    if not metadata:
        return findings

    for finding in findings:
        advisory = finding.get("security_advisory") or {}
        ghsa_id = advisory.get("ghsa_id", "")
        cve_id = advisory.get("cve_id", "")
        meta = metadata.get(ghsa_id) or metadata.get(cve_id)
        if not meta:
            continue

        if meta.get("published_at"):
            advisory["published_at"] = meta["published_at"]
            finding["created_at"] = meta["published_at"]
        if meta.get("updated_at"):
            advisory["updated_at"] = meta["updated_at"]
            finding["updated_at"] = meta["updated_at"]

        # Fill in missing cve_id from GitHub advisory identifiers
        if not advisory.get("cve_id") and ghsa_id:
            gh_meta = metadata.get(ghsa_id)
            if gh_meta:
                # Check if any alias key is a CVE
                for key in metadata:
                    if key.startswith("CVE-") and metadata[key] is gh_meta:
                        advisory["cve_id"] = key
                        break

        cvss = advisory.get("cvss") or {}
        if not cvss.get("score") and meta.get("cvss_score"):
            advisory["cvss"] = {"score": meta["cvss_score"], "vector_string": meta.get("cvss_vector")}

        if meta.get("html_url") and not finding.get("html_url"):
            finding["html_url"] = meta["html_url"]

        # Enrich description (Grype often only has a one-liner)
        if meta.get("description") and len(meta["description"]) > len(advisory.get("description", "")):
            advisory["description"] = meta["description"]

        # Enrich summary
        if meta.get("summary") and (not advisory.get("summary") or advisory["summary"] == advisory.get("description", "")):
            advisory["summary"] = meta["summary"]

        # Enrich references (Grype usually only has one dataSource link)
        if meta.get("references"):
            existing_urls = {r.get("url") for r in advisory.get("references", []) if r.get("url")}
            for ref in meta["references"]:
                if ref.get("url") and ref["url"] not in existing_urls:
                    advisory.setdefault("references", []).append(ref)
                    existing_urls.add(ref["url"])

        # Enrich affected version range
        vuln = finding.get("security_vulnerability") or {}
        if meta.get("vulnerable_version_range") and not vuln.get("vulnerable_version_range"):
            vuln["vulnerable_version_range"] = meta["vulnerable_version_range"]

        # Enrich patched version
        if meta.get("first_patched_version") and not vuln.get("first_patched_version"):
            pv = meta["first_patched_version"]
            vuln["first_patched_version"] = {"identifier": pv} if isinstance(pv, str) else pv

        # Add CWEs
        if meta.get("cwes"):
            advisory["cwes"] = meta["cwes"]

    return findings
