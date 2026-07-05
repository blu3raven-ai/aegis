"""Dependencies matching utilities — finding deduplication."""
from __future__ import annotations

import logging
from typing import Any

from src.shared.finding_merger import merge_findings as _generic_merge

logger = logging.getLogger(__name__)


def _dependencies_dedup_key(f: dict[str, Any]) -> str:
    advisory = f.get("security_advisory") or {}
    dep = f.get("dependency") or {}
    pkg = (dep.get("package") or {}).get("name", "")
    manifest = dep.get("manifest_path", "")
    return f"{advisory.get('ghsa_id', '')}::{pkg}::{manifest}"


def _dependencies_cvss(f: dict[str, Any]) -> float:
    return ((f.get("security_advisory") or {}).get("cvss") or {}).get("score") or 0


def _dependencies_merge_extra(existing: dict[str, Any], new: dict[str, Any]) -> None:
    existing_sources = set(existing.get("matched_by") or [])
    new_sources = set(new.get("matched_by") or [])
    existing["matched_by"] = sorted(existing_sources | new_sources)


def merge_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate dependency findings by advisory ID + package + manifest."""
    return _generic_merge(findings, _dependencies_dedup_key, _dependencies_cvss, _dependencies_merge_extra)
