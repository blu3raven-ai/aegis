"""Pydantic schemas for onboarding wizard state.

State is persisted as config["onboarding"] inside the existing AppConfig row
(no new DB table required).
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel

StepId = Literal["welcome", "connect_source", "smoke_test", "alerts", "policy"]

STEP_ORDER: list[StepId] = [
    "welcome",
    "connect_source",
    "smoke_test",
    "alerts",
    "policy",
]


class StepState(BaseModel):
    completed: bool = False
    skipped: bool = False
    data: dict[str, Any] = {}


class OnboardingState(BaseModel):
    steps: dict[StepId, StepState] = {
        "welcome": StepState(),
        "connect_source": StepState(),
        "smoke_test": StepState(),
        "alerts": StepState(),
        "policy": StepState(),
    }
    # True once the user has clicked "Finish" at the end of step 5
    dismissed: bool = False

    @property
    def is_complete(self) -> bool:
        return self.dismissed
