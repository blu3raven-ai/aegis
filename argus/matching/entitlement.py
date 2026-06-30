"""Premium entitlement — does an org's subscription cover premium results?

Auth proves *who* a caller is (its org, from the verified token); entitlement
decides *whether* that org gets premium data. They compose: a caller must be
authenticated **and** entitled to receive premium matches.

The shipped default entitles every authenticated org — auth is then the only
gate, which is correct for a single-tier deployment. To gate premium behind a
paid tier, return a checker backed by your subscription/billing system from
``default_entitlement_checker``; an unentitled org transparently falls back to
the free OSV match (an empty premium response), never an error.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class EntitlementChecker(Protocol):
    """Decide whether ``org_id`` may receive premium results for ``surface``."""

    def is_entitled(self, org_id: str, surface: str) -> bool:
        ...


class AllowAllEntitlement:
    """Default: every authenticated org is entitled. Not a paywall."""

    def is_entitled(self, org_id: str, surface: str) -> bool:
        return True


def default_entitlement_checker() -> EntitlementChecker:
    """Return the entitlement checker (the swap point).

    Placeholder: ``AllowAllEntitlement``. Return a subscription-backed checker
    here to gate premium results behind a paid tier.
    """
    return AllowAllEntitlement()
