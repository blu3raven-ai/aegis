"""Subject-agnostic condition-evaluation engine.

Evaluates a predicate tree (all/any groupings plus leaf operators) against an
arbitrary subject. Callers supply a `getter` callable to resolve field names on
the subject, which keeps this module decoupled from any specific domain type
(Finding, Rule, etc.).

Leaf operators: eq, neq, in, nin, contains, not_contains, gt, gte, lt, lte.
Ordinal comparisons (gt/gte/lt/lte) on severity-like strings use the rank map
so that string severities compare intuitively.
"""
from __future__ import annotations

from typing import Any, Callable

__all__ = ["evaluate_condition"]

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "none": -1,
}


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


def evaluate_condition(
    condition: dict[str, Any],
    subject: Any,
    getter: Callable[[Any, str], Any],
) -> bool:
    """Recursively evaluate a predicate tree against a subject.

    A node is either a grouping:
        {"all": [...child nodes...]}   — all children must be true (AND)
        {"any": [...child nodes...]}   — at least one child must be true (OR)

    Or a leaf:
        {"field": "<name>", "op": "<operator>", "value": <scalar or list>}

    Empty groups evaluate to True (vacuous truth) so that a rule with no
    conditions matches every subject — useful for "catch-all" rules.
    """
    if not condition:
        return True

    if "all" in condition:
        children = condition["all"]
        return all(evaluate_condition(child, subject, getter) for child in children)

    if "any" in condition:
        children = condition["any"]
        if not children:
            return True
        return any(evaluate_condition(child, subject, getter) for child in children)

    # Leaf node
    field_name = condition.get("field")
    op = condition.get("op")
    rule_val = condition.get("value")

    if field_name is None or op is None:
        raise ValueError(f"malformed leaf condition: {condition!r}")

    field_val = getter(subject, field_name)
    return _apply_op(op, field_val, rule_val)
