"""Shared Grype output parsing helpers — ID extraction and CVSS scoring."""
from __future__ import annotations

from typing import Any


def extract_ghsa_id(vuln_id: str, aliases: list[Any]) -> str | None:
    """Extract GHSA ID from a vulnerability ID or its aliases/related list."""
    if vuln_id.startswith("GHSA-"):
        return vuln_id
    for alias in aliases:
        aid = alias if isinstance(alias, str) else (alias.get("id", "") if isinstance(alias, dict) else "")
        if aid.startswith("GHSA-"):
            return aid
    return None


def extract_cve_id(vuln_id: str, aliases: list[Any]) -> str | None:
    """Extract CVE ID from a vulnerability ID or its aliases/related list."""
    if vuln_id.startswith("CVE-"):
        return vuln_id
    for alias in aliases:
        aid = alias if isinstance(alias, str) else (alias.get("id", "") if isinstance(alias, dict) else "")
        if aid.startswith("CVE-"):
            return aid
    return None


def max_cvss_score(cvss_entries: list[dict[str, Any]]) -> float | None:
    """Extract the highest CVSS base score from a list of CVSS entries."""
    scores: list[float] = []
    for entry in cvss_entries:
        metrics = entry.get("metrics") or {}
        score = metrics.get("baseScore")
        if isinstance(score, (int, float)):
            scores.append(float(score))
    return max(scores) if scores else None
