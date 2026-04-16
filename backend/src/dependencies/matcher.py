"""Dependencies matching utilities — finding deduplication and manifest enrichment."""
from __future__ import annotations

import logging
from typing import Any

from src.shared.finding_merger import merge_findings as _generic_merge

logger = logging.getLogger(__name__)

CONTEXT_LINES = 7


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


def enrich_with_manifest_snippets(
    findings: list[dict[str, Any]],
    manifests: dict[str, str],
) -> list[dict[str, Any]]:
    """Add manifest_snippet and manifest_match_line to findings from stored manifest content."""
    for f in findings:
        dep = f.get("dependency") or {}
        manifest_path = dep.get("manifest_path", "")
        pkg_name = (dep.get("package") or {}).get("name", "")

        if not manifest_path or not pkg_name:
            continue

        clean_path = manifest_path.lstrip("/")
        safe_key = manifest_path.replace("/", "__")
        safe_key_clean = clean_path.replace("/", "__")
        content = manifests.get(clean_path) or manifests.get(manifest_path) or manifests.get(safe_key) or manifests.get(safe_key_clean)
        if not content:
            continue

        lines = content.split("\n")
        match_line = None
        for i, line in enumerate(lines, 1):
            if pkg_name.lower() in line.lower():
                match_line = i
                break

        if match_line:
            start = max(0, match_line - 1 - CONTEXT_LINES)
            end = min(len(lines), match_line + CONTEXT_LINES)
            snippet = "\n".join(lines[start:end])
        else:
            snippet = "\n".join(lines[:15])
            match_line = 0

        f["manifest_snippet"] = snippet
        f["manifest_match_line"] = match_line

    return findings
