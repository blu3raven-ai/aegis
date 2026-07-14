"""Scope-match declared accepted-risks against a single finding.

A risk with no scope keys applies to every finding on the source. Any provided
scope key (path_glob / rule_id / scanner) must match for the risk to apply; keys
combine with AND. Pure function — no LLM, no I/O — so the match is deterministic
and auditable before the skeptic ever confirms applicability.
"""
from __future__ import annotations

import fnmatch
from typing import Any


def _finding_rule(finding: dict[str, Any]) -> str:
    return str(finding.get("rule") or finding.get("rule_id") or finding.get("check_id") or "")


def accepted_risks_for_finding(
    finding: dict[str, Any], accepted_risks: list[dict[str, Any]] | None
) -> list[dict[str, Any]]:
    if not accepted_risks:
        return []
    path = str(finding.get("file") or finding.get("file_path") or "")
    rule = _finding_rule(finding)
    scanner = str(finding.get("scanner") or "")
    matched: list[dict[str, Any]] = []
    for risk in accepted_risks:
        glob = risk.get("path_glob")
        if glob and not fnmatch.fnmatch(path, str(glob)):
            continue
        if risk.get("rule_id") and str(risk["rule_id"]) != rule:
            continue
        if risk.get("scanner") and str(risk["scanner"]) != scanner:
            continue
        matched.append(risk)
    return matched
