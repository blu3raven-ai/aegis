"""Generic finding deduplication and merge logic.

Shared by SCA and Container scanning matchers. Each tool provides its own
key builder, CVSS extractor, and optional merge hook for tool-specific fields.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


def merge_findings(
    findings: list[dict[str, Any]],
    key_fn: Callable[[dict[str, Any]], str],
    cvss_fn: Callable[[dict[str, Any]], float],
    merge_extra: Callable[[dict[str, Any], dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    """Deduplicate findings by key_fn, merging duplicates.

    For duplicates with the same key:
    - Prefer the finding with a fix version
    - Prefer higher CVSS score (via cvss_fn)
    - Prefer longer description
    - Call merge_extra(winner, duplicate) if provided for tool-specific syncing
    """
    seen: dict[str, dict[str, Any]] = {}

    for f in findings:
        key = key_fn(f)
        if key not in seen:
            seen[key] = f
            continue

        existing = seen[key]

        # Prefer finding with fix version
        existing_fix = (existing.get("security_vulnerability") or {}).get("first_patched_version")
        new_fix = (f.get("security_vulnerability") or {}).get("first_patched_version")
        if not existing_fix and new_fix:
            existing.setdefault("security_vulnerability", {})["first_patched_version"] = new_fix

        # Prefer higher CVSS score
        new_cvss = cvss_fn(f)
        existing_cvss = cvss_fn(existing)
        if new_cvss > existing_cvss:
            existing.setdefault("security_advisory", {})["cvss"] = f.get("security_advisory", {}).get("cvss")

        # Prefer longer description
        existing_desc = (existing.get("security_advisory") or {}).get("description", "")
        new_desc = (f.get("security_advisory") or {}).get("description", "")
        if len(new_desc) > len(existing_desc):
            adv = existing.setdefault("security_advisory", {})
            adv["description"] = new_desc
            adv["summary"] = (f.get("security_advisory") or {}).get("summary", "")

        # Tool-specific merge hook
        if merge_extra:
            merge_extra(existing, f)

    merged = list(seen.values())
    logger.info("Merged %d findings into %d after deduplication", len(findings), len(merged))
    return merged
