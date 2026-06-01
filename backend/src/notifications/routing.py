"""Finding-to-channel routing engine for Phase 42 notification routing rules.

Rules are evaluated in ascending priority order (lower number = higher
priority). The first matching enabled rule wins — "first match wins" semantics
keep the routing predictable for v1.

evaluate_condition handles the full predicate tree recursively:
  - top-level and nested all/any groupings
  - leaf operators: eq, neq, in, nin, contains, not_contains, gt, gte, lt, lte

If no rule matches, callers must fall back to default channel fanout so users
with zero routing rules continue to receive notifications as before.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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
    org_id: str


# ── Predicate evaluation ──────────────────────────────────────────────────────

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "none": -1,
}

_FINDING_FIELDS: frozenset[str] = frozenset(
    {"severity", "scanner", "repo_id", "repo_labels", "cve_id", "chain_role"}
)


def _get_field(finding: Finding, field_name: str) -> Any:
    if field_name not in _FINDING_FIELDS:
        raise ValueError(f"unknown finding field: {field_name!r}")
    return getattr(finding, field_name)


def _apply_op(op: str, field_val: Any, rule_val: Any) -> bool:
    """Evaluate a single leaf operator against the actual field value.

    Numeric comparisons on severity use the rank map so that
    gt/gte/lt/lte work intuitively on string severity labels.
    """
    if op == "eq":
        return field_val == rule_val
    if op == "neq":
        return field_val != rule_val
    if op == "in":
        return field_val in rule_val
    if op == "nin":
        return field_val not in rule_val
    if op == "contains":
        # list field contains the value; or string field contains substring
        if isinstance(field_val, list):
            return rule_val in field_val
        return rule_val in str(field_val)
    if op == "not_contains":
        if isinstance(field_val, list):
            return rule_val not in field_val
        return rule_val not in str(field_val)
    # Ordinal operators — resolve severity strings to ranks, fall back to raw value
    if op in ("gt", "gte", "lt", "lte"):
        lhs = _SEVERITY_RANK.get(str(field_val), field_val) if isinstance(field_val, str) else field_val
        rhs = _SEVERITY_RANK.get(str(rule_val), rule_val) if isinstance(rule_val, str) else rule_val
        if op == "gt":
            return lhs > rhs
        if op == "gte":
            return lhs >= rhs
        if op == "lt":
            return lhs < rhs
        if op == "lte":
            return lhs <= rhs
    raise ValueError(f"unknown operator: {op!r}")


def evaluate_condition(condition: dict[str, Any], finding: Finding) -> bool:
    """Recursively evaluate a predicate tree against a finding.

    A node is either a grouping:
        {"all": [...child nodes...]}   — all children must be true (AND)
        {"any": [...child nodes...]}   — at least one child must be true (OR)

    Or a leaf:
        {"field": "<name>", "op": "<operator>", "value": <scalar or list>}

    Empty groups evaluate to True (vacuous truth) so that a rule with no
    conditions routes every finding — useful for "catch-all" rules.
    """
    if not condition:
        return True

    if "all" in condition:
        children = condition["all"]
        return all(evaluate_condition(child, finding) for child in children)

    if "any" in condition:
        children = condition["any"]
        if not children:
            return True
        return any(evaluate_condition(child, finding) for child in children)

    # Leaf node
    field_name = condition.get("field")
    op = condition.get("op")
    rule_val = condition.get("value")

    if field_name is None or op is None:
        raise ValueError(f"malformed leaf condition: {condition!r}")

    field_val = _get_field(finding, field_name)
    return _apply_op(op, field_val, rule_val)


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
