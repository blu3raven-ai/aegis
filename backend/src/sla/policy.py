"""SLA policy data types and defaults for Phase 47."""
from __future__ import annotations

from dataclasses import dataclass

VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low"})


@dataclass
class SlaPolicy:
    severity: str
    deadline_days: int
    enabled: bool

    def validate(self) -> None:
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if self.deadline_days <= 0:
            raise ValueError("deadline_days must be greater than 0")


DEFAULT_POLICIES: list[SlaPolicy] = [
    SlaPolicy("critical", 7, True),
    SlaPolicy("high", 14, True),
    SlaPolicy("medium", 30, True),
    SlaPolicy("low", 90, True),
]
