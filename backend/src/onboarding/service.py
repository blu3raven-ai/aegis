"""Business logic for the onboarding wizard.

State is stored under the "onboarding" key in the existing app_config JSONB
blob — no new DB table needed. The org_id parameter is accepted for API
symmetry (multi-org future-proofing) but the singleton AppConfig row is
shared; a single installation is assumed.
"""
from __future__ import annotations

from typing import Any

from src.onboarding.models import OnboardingState, StepId, STEP_ORDER
from src.shared.config import read_app_config, write_app_config


def _load(org_id: str) -> OnboardingState:
    config = read_app_config()
    raw = config.get("onboarding")
    if not raw:
        return OnboardingState()
    try:
        return OnboardingState.model_validate(raw)
    except Exception:
        return OnboardingState()


def _save(org_id: str, state: OnboardingState) -> None:
    config = read_app_config()
    config["onboarding"] = state.model_dump()
    write_app_config(config, "onboarding.state.updated")


def get_state(org_id: str) -> OnboardingState:
    return _load(org_id)


def complete_step(org_id: str, step_id: StepId, data: dict[str, Any]) -> OnboardingState:
    state = _load(org_id)
    state.steps[step_id].completed = True
    state.steps[step_id].skipped = False
    state.steps[step_id].data = data
    _save(org_id, state)
    return state


def skip_step(org_id: str, step_id: StepId) -> OnboardingState:
    state = _load(org_id)
    state.steps[step_id].skipped = True
    _save(org_id, state)
    return state


def dismiss(org_id: str) -> OnboardingState:
    """Mark wizard as fully dismissed — hides sidebar entry permanently."""
    state = _load(org_id)
    state.dismissed = True
    _save(org_id, state)
    return state


def is_complete(org_id: str) -> bool:
    return _load(org_id).is_complete
