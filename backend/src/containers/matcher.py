# backend/src/containers/matcher.py
"""Deduplicate and enrich container scanning findings."""
from __future__ import annotations

from typing import Any

from src.shared.finding_merger import merge_findings as _generic_merge


def _container_dedup_key(f: dict[str, Any]) -> str:
    adv = f.get("security_advisory", {})
    dep = f.get("dependency", {}).get("package", {})
    return f"{adv.get('ghsa_id', '')}::{dep.get('name', '')}::{dep.get('ecosystem', '')}"


def _container_cvss(f: dict[str, Any]) -> float:
    return f.get("security_advisory", {}).get("cvss") or 0


def _container_merge_extra(existing: dict[str, Any], new: dict[str, Any]) -> None:
    # Merge matched_by
    src = new.get("scanner", "osv")
    if src not in existing.get("matched_by", []):
        existing.setdefault("matched_by", []).append(src)

    # Sync fixState if fix version was adopted
    existing_fix = existing.get("security_vulnerability", {}).get("first_patched_version")
    new_fix = new.get("security_vulnerability", {}).get("first_patched_version")
    if not existing_fix and new_fix:
        existing["fixState"] = new.get("fixState", existing.get("fixState"))

    # Sync cvss_vector if higher CVSS was adopted
    new_cvss = new.get("security_advisory", {}).get("cvss") or 0
    ex_cvss = existing.get("security_advisory", {}).get("cvss") or 0
    if new_cvss > ex_cvss:
        existing.setdefault("security_advisory", {})["cvss_vector"] = new.get("security_advisory", {}).get("cvss_vector")


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate container findings by advisory+package+ecosystem."""
    for f in findings:
        f.setdefault("matched_by", [f.get("scanner", "osv")])
    return _generic_merge(findings, _container_dedup_key, _container_cvss, _container_merge_extra)
