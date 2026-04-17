"""Convenience helpers for checking tier limits and feature flags."""

from __future__ import annotations

from fastapi import HTTPException, Request

from .types import TIER_LABELS, TIER_LIMITS, Tier


def get_tier(request: Request) -> Tier:
    """Get tier from request.state, defaulting to COMMUNITY."""
    return getattr(request.state, "tier", Tier.COMMUNITY)


def check_limit(request: Request, limit_key: str, current_count: int) -> None:
    """Raise 403 if *current_count* >= the tier's limit for *limit_key*.

    A limit value of ``None`` means unlimited (never blocked).
    """
    tier = get_tier(request)
    limits = TIER_LIMITS[tier]
    max_allowed = limits.get(limit_key)
    if max_allowed is None:
        return  # unlimited
    if current_count >= max_allowed:
        label = TIER_LABELS.get(tier, tier.value.title())
        raise HTTPException(
            status_code=403,
            detail=(
                f"You have reached the {label} plan limit for {limit_key} "
                f"({max_allowed}). Please upgrade to increase this limit."
            ),
        )


def check_feature(request: Request, feature_key: str) -> None:
    """Raise 403 if the feature is not enabled for the current tier."""
    tier = get_tier(request)
    limits = TIER_LIMITS[tier]
    enabled = limits.get(feature_key, False)
    if not enabled:
        label = TIER_LABELS.get(tier, tier.value.title())
        raise HTTPException(
            status_code=403,
            detail=(
                f"This feature is not available on the {label} plan. "
                "Please upgrade to continue."
            ),
        )
