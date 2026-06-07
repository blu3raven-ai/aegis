"""Merge Opengrep + Joern findings that flag the same (file, line, cwe).

Joern produces interprocedural taint findings; Opengrep produces pattern
matches. When both engines flag the same CWE at the same code location,
collapse into a single finding tagged engine="both" with the dataflow
trace from Joern (Opengrep has none).
"""
from __future__ import annotations

import re
from typing import Any

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Matches the canonical CWE-N prefix in tags like "CWE-89" or
# "CWE-494: Download of Code Without Integrity Check".
_CWE_PREFIX = re.compile(r"^(CWE-\d+)", re.IGNORECASE)


def _canonical_cwe(value: str) -> str:
    """Return the canonical `cwe-<n>` form, or empty string if not parseable."""
    m = _CWE_PREFIX.match(value.strip())
    return m.group(1).lower() if m else ""


def _max_severity(a: str | None, b: str | None) -> str | None:
    a_rank = _SEV_ORDER.get((a or "").lower(), 0)
    b_rank = _SEV_ORDER.get((b or "").lower(), 0)
    return a if a_rank >= b_rank else b


def _merge_key(finding: dict[str, Any]) -> tuple[str, str, int, str]:
    """Build a merge key: (repo, file, start_line, canonical_cwe).

    Falls back to rule_id when no CWE is set — preserves legacy behaviour
    for findings without CWE tagging.
    """
    repo = str(finding.get("repo_full_name") or "")
    file_path = str(finding.get("file_path") or "")
    line = int(finding.get("start_line") or 0)
    canonical = _canonical_cwe(_first_cwe(finding))
    discriminator = canonical or str(finding.get("rule_id") or "")
    return (repo, file_path, line, discriminator)


def _first_cwe(raw: dict[str, Any]) -> str:
    cwe_list = raw.get("cwe") or []
    if isinstance(cwe_list, list) and cwe_list:
        return str(cwe_list[0])
    if isinstance(cwe_list, str):
        return cwe_list
    return ""


def merge_engine_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse opengrep + joern findings sharing (file, line, cwe).

    - severity = max of both
    - engine = "both" when engines differ, else the single engine
    - dataflow_trace = from whichever finding has one (Joern)
    - rule_id = engine-agnostic surrogate `sast:cwe-<n>` when CWE is set,
      so the lifecycle identity_key stays stable when one engine drops or
      gains coverage between scans. Findings without CWE keep their
      original rule_id (legacy / non-CWE behaviour unchanged).
    - _rule_ids accumulates all original rule_ids from merged sources
      so detail.ruleIds preserves cross-engine attribution.
    """
    by_key: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for raw in findings:
        key = _merge_key(raw)

        # Rewrite rule_id to the stable surrogate form before storing so
        # identity_key derivation downstream sees the engine-agnostic id.
        # Canonicalize to `cwe-<n>` so descriptive cwe strings like
        # "CWE-494: Download of Code Without Integrity Check" still
        # collapse onto the same surrogate.
        cwe_canonical = _canonical_cwe(_first_cwe(raw))
        original_rule_id = raw.get("rule_id", "")
        if cwe_canonical:
            surrogate_rule_id = f"sast:{cwe_canonical}"
            raw_for_storage = dict(raw)
            raw_for_storage["rule_id"] = surrogate_rule_id
        else:
            raw_for_storage = raw

        existing = by_key.get(key)
        if existing is None:
            merged = dict(raw_for_storage)
            merged["_rule_ids"] = [original_rule_id] if original_rule_id else []
            by_key[key] = merged
            continue

        existing_engine = existing.get("engine") or "opengrep"
        new_engine = raw.get("engine") or "opengrep"
        if existing_engine != new_engine:
            existing["engine"] = "both"

        existing["severity"] = _max_severity(existing.get("severity"), raw.get("severity"))

        if not existing.get("dataflow_trace") and raw.get("dataflow_trace"):
            existing["dataflow_trace"] = raw["dataflow_trace"]

        if original_rule_id and original_rule_id not in existing["_rule_ids"]:
            existing["_rule_ids"].append(original_rule_id)

    return list(by_key.values())
