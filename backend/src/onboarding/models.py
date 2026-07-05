"""Pydantic schemas for onboarding wizard state.

State is persisted as config["onboarding"] inside the existing AppConfig row
(no new DB table required).
"""
from __future__ import annotations

from typing import Any, Literal, get_args

from pydantic import BaseModel, model_validator

StepId = Literal["connect_source", "pick_repos", "smoke_test"]

STEP_ORDER: list[StepId] = [
    "connect_source",
    "pick_repos",
    "smoke_test",
]


class StepState(BaseModel):
    completed: bool = False
    skipped: bool = False
    data: dict[str, Any] = {}


class OnboardingState(BaseModel):
    steps: dict[StepId, StepState] = {
        "connect_source": StepState(),
        "pick_repos": StepState(),
        "smoke_test": StepState(),
    }
    # True once the user has clicked "Finish" at the end of the last step
    dismissed: bool = False

    # Strip unrecognised step keys from persisted state so old rows
    # (with "welcome", "alerts", "policy") load without a ValidationError,
    # and backfill any newly-added steps that are missing from stored state.
    @model_validator(mode="before")
    @classmethod
    def _migrate_steps(cls, data: Any) -> Any:
        if isinstance(data, dict) and "steps" in data and isinstance(data["steps"], dict):
            valid = set(get_args(StepId))
            filtered = {k: v for k, v in data["steps"].items() if k in valid}
            # Ensure every current step is present (backfill new steps as empty)
            for step in valid:
                filtered.setdefault(step, {})
            data = {**data, "steps": filtered}
        return data

    @property
    def is_complete(self) -> bool:
        return self.dismissed
