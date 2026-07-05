"""Rule interface definitions for the correlation engine.

Every rule is a Python class implementing the Rule Protocol. Rules are
registered in rules/__init__.py and dispatched by the engine based on
their triggers list.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from src.argus.connector import ArgusConnector
    from src.correlation.emit_interface import EmitInterface
    from src.correlation.state import CorrelationState


@dataclass
class RuleContext:
    """Injected into every rule.evaluate() call.

    argus is always an ArgusConnector instance — either the real one (Mode B)
    or NullArgusConnector (Mode A / heuristic fallback). Rules never need to
    check for None; they always get a connector with working fallbacks.
    """
    state: "CorrelationState"
    argus: "ArgusConnector"  # NullArgusConnector when Argus is unconfigured
    emit: "EmitInterface"


class Rule(Protocol):
    """Protocol every rule must satisfy.

    triggers: list of event_type strings this rule subscribes to.
    name: stable identifier used in idempotency keys and logs.
    """
    triggers: list[str]
    name: str

    def evaluate(self, event: dict, ctx: RuleContext) -> None:
        """Evaluate rule against a single event.

        event is the raw dict from EventStream.subscribe() (fields:
        event_id, event_type, org_id, source_component, timestamp_utc, payload).

        Implementations must be idempotent — the engine wraps evaluate()
        with idempotency checks but rules should not assume they are called
        at most once per event.
        """
        ...
