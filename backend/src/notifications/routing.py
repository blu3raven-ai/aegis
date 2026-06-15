"""Finding-to-channel routing engine for Phase 42 notification routing rules.

Rules are evaluated in ascending priority order (lower number = higher
priority). The first matching enabled rule wins — "first match wins" semantics
keep the routing predictable for v1.

Predicate-tree evaluation (all/any groups, leaf operators) is delegated to
src.rules_engine.conditions. This module owns only the Finding-specific
adapter: the field whitelist and the getter used by the shared engine.

If no rule matches, callers must fall back to default channel fanout so users
with zero routing rules continue to receive notifications as before.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.rules_engine.conditions import evaluate_condition as _evaluate_condition

__all__ = [
    "Finding",
    "Rule",
    "evaluate_condition",
    "route_finding",
]


@dataclass
class Finding:
    severity: str
    scanner: str
    repo_id: str
    repo_labels: list[str] = field(default_factory=list)
    cve_id: str | None = None
    chain_role: str | None = None  # 'entrypoint' | 'pivot' | 'sink' | None


@dataclass
class Rule:
    id: str
    name: str
    enabled: bool
    priority: int
    channel_id: int
    conditions: dict[str, Any]


# ── Predicate evaluation ──────────────────────────────────────────────────────

_FINDING_FIELDS: frozenset[str] = frozenset(
    {"severity", "scanner", "repo_id", "repo_labels", "cve_id", "chain_role"}
)


def _get_field(finding: Finding, field_name: str) -> Any:
    if field_name not in _FINDING_FIELDS:
        raise ValueError(f"unknown finding field: {field_name!r}")
    return getattr(finding, field_name)


def evaluate_condition(condition: dict[str, Any], finding: Finding) -> bool:
    """Evaluate a predicate tree against a Finding.

    Thin wrapper around the subject-agnostic engine in
    ``src.rules_engine.conditions`` that binds the finding-specific field
    resolver. Kept here so existing callers can continue to import
    ``evaluate_condition`` from ``src.notifications.routing``.
    """
    return _evaluate_condition(condition, finding, _get_field)


# ── Routing ───────────────────────────────────────────────────────────────────


def route_finding(finding: Finding, rules: list[Rule]) -> list[int]:
    """Return channel_ids the finding should be sent to.

    Rules are evaluated in ascending priority order. The first matching enabled
    rule claims the finding and returns its channel_id. An empty list means no
    rule matched — callers should fall back to the default all-channels fanout.
    """
    sorted_rules = sorted(
        (r for r in rules if r.enabled),
        key=lambda r: r.priority,
    )
    for rule in sorted_rules:
        try:
            if evaluate_condition(rule.conditions, finding):
                return [rule.channel_id]
        except Exception:
            # Malformed condition should never block other rules from firing
            continue
    return []
