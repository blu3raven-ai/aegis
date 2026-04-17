from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Tier(str, Enum):
    COMMUNITY = "community"
    ENTERPRISE = "enterprise"

    @staticmethod
    def _rank(tier: Tier) -> int:
        return {"community": 0, "enterprise": 1}[tier.value]

    def __lt__(self, other: Any) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self._rank(self) < self._rank(other)

    def __le__(self, other: Any) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self._rank(self) <= self._rank(other)

    def __gt__(self, other: Any) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self._rank(self) > self._rank(other)

    def __ge__(self, other: Any) -> bool:
        if not isinstance(other, Tier):
            return NotImplemented
        return self._rank(self) >= self._rank(other)


@dataclass(frozen=True)
class LicenseClaims:
    tier: Tier
    org: str
    max_users: int | None
    max_orgs: int | None
    issued_at: str
    expires_at: str
    license_id: str
    addons: tuple[str, ...] = ()


TIER_LABELS: dict[Tier, str] = {
    Tier.COMMUNITY: "Community",
    Tier.ENTERPRISE: "Enterprise",
}

TIER_LIMITS: dict[Tier, dict[str, Any]] = {
    Tier.COMMUNITY: {
        "max_users": None,
        "max_remote_runners": None,
        "max_source_connections": None,
        "custom_roles": True,
        "teams": True,
        "insights_tab": True,
        "health_tab": True,
        "ai_review": True,
        "custom_scan_schedule": True,
        "mfa": False,
        "sso": False,
        "audit_log": False,
        "integrations": False,
        "sbom_export": False,
        "data_retention_days": None,
    },
    Tier.ENTERPRISE: {
        "max_users": None,
        "max_remote_runners": None,
        "max_source_connections": None,
        "custom_roles": True,
        "teams": True,
        "insights_tab": True,
        "health_tab": True,
        "ai_review": True,
        "custom_scan_schedule": True,
        "mfa": True,
        "sso": True,
        "audit_log": True,
        "integrations": True,
        "sbom_export": True,
        "data_retention_days": None,
    },
}
