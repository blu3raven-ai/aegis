"""Pure extractor for promoted typed columns on findings.

Tool-agnostic: the fallback chain per field covers every shape ingest
produces (camelCase from current adapters + snake_case from any legacy rows).
"""
from __future__ import annotations

from typing import Any


def _first_str(d: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """Return the first truthy string value from keys, or None."""
    for k in keys:
        v = d.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def extract_queryable_fields(detail: dict[str, Any] | None) -> dict[str, str | None]:
    """Return the 5 typed-column values for a finding's detail dict.

    Returns the 5-key shape with all values None on empty/None input.
    All output values are str | None (truthy strings only — empty strings
    are treated as missing for the column).
    """
    if not detail:
        return {
            "cve_id": None,
            "file_path": None,
            "title": None,
            "rule_name": None,
            "package_name": None,
        }
    return {
        "cve_id": _first_str(detail, ("cveId", "cve_id", "cve")),
        "file_path": _first_str(detail, ("filePath", "file_path", "path", "manifestPath")),
        "title": _first_str(detail, ("title",)),
        "rule_name": _first_str(detail, ("ruleName", "rule_name")),
        "package_name": _first_str(detail, ("packageName", "package_name")),
    }
