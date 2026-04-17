"""Resolve the active license tier from a stored key."""

from __future__ import annotations

import logging

from .keys import LicenseError, decode_license
from .types import LicenseClaims, Tier

logger = logging.getLogger(__name__)


def resolve_current_tier(
    license_key: str | None,
    public_key: str,
) -> tuple[Tier, LicenseClaims | None]:
    """Resolve the current tier from a license key.

    Returns (Tier.COMMUNITY, None) if no key, invalid key, or expired key.
    """
    if not license_key:
        return Tier.COMMUNITY, None

    try:
        claims = decode_license(license_key, public_key)
        return claims.tier, claims
    except LicenseError as exc:
        logger.warning("[!] License key rejected: %s", exc)
        return Tier.COMMUNITY, None
