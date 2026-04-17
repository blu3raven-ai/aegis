"""Tier gate: raise 403 if the caller's tier is too low."""

from __future__ import annotations

from fastapi import HTTPException

from .types import Tier, TIER_LABELS


def require_tier(current_tier: Tier, required_tier: Tier) -> None:
    """Raise HTTPException(403) if *current_tier* is below *required_tier*."""
    if current_tier >= required_tier:
        return

    label = TIER_LABELS.get(required_tier, required_tier.value.title())
    raise HTTPException(
        status_code=403,
        detail=(
            f"This feature requires the {label} plan or above. "
            "Please upgrade to continue."
        ),
    )
