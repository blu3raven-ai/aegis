"""Category-specific action JSONB schemas validated on create/update."""
from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, Field, TypeAdapter


class SlaEscalation(BaseModel):
    at_hours: int = Field(ge=1)
    channel_id: int


class SlaAction(BaseModel):
    deadline_days: int = Field(ge=1, le=3650)
    escalations: list[SlaEscalation] = Field(default_factory=list)


class RequireScannersAction(BaseModel):
    type: Literal["require_scanners"]
    required_scanners: list[
        Literal["dependencies_scanning", "code_scanning", "container_scanning", "secret_scanning"]
    ] = Field(min_length=1)


class StaleAlertAction(BaseModel):
    type: Literal["stale_alert"]
    stale_after_days: int = Field(ge=1, le=365)
    # Notify-channel delivery and auto-retrigger are not yet wired: a stale
    # alert opens a violation regardless, so a channel is optional.
    alert_channel_id: int | None = None
    auto_retrigger: bool = False


ScannerCoverageAction = Annotated[
    Union[RequireScannersAction, StaleAlertAction],
    Field(discriminator="type"),
]


class AutoDismissAction(BaseModel):
    reason: str = Field(min_length=3, max_length=200)
    audit_note: str | None = Field(default=None, max_length=500)
    rate_alarm_pct: float = Field(default=50.0, ge=1.0, le=100.0)
    rate_alarm_window_minutes: int = Field(default=60, ge=5, le=10080)


class ArchiveAction(BaseModel):
    type: Literal["archive"]
    after_days: int = Field(ge=30, le=3650)


class DeleteAction(BaseModel):
    type: Literal["delete"]
    after_days: int = Field(ge=90, le=3650)


DataRetentionAction = Annotated[
    Union[ArchiveAction, DeleteAction],
    Field(discriminator="type"),
]


_ACTION_VALIDATORS: dict[str, TypeAdapter] = {
    "sla": TypeAdapter(SlaAction),
    "scanner_coverage": TypeAdapter(ScannerCoverageAction),
    "auto_dismiss": TypeAdapter(AutoDismissAction),
    "data_retention": TypeAdapter(DataRetentionAction),
}


_RESERVED_CATEGORIES: frozenset[str] = frozenset()
_SUPPORTED_CATEGORIES = frozenset({"sla", "scanner_coverage", "auto_dismiss", "data_retention"})
_ALL_CATEGORIES = _SUPPORTED_CATEGORIES | _RESERVED_CATEGORIES


def validate_action_for_category(category: str, action: dict) -> BaseModel:
    """Return the validated Pydantic model for the action.

    Raises ValueError if the category isn't supported in this phase or if
    the action payload doesn't match the schema.
    """
    if category not in _ALL_CATEGORIES:
        raise ValueError(f"unknown rule category: {category!r}")
    if category in _RESERVED_CATEGORIES:
        raise ValueError(
            f"rule category {category!r} is reserved for a future phase and not yet supported"
        )
    return _ACTION_VALIDATORS[category].validate_python(action)
