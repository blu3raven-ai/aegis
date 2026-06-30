"""Premium dependency→advisory matching for the Argus service.

This is the moat half of ``/v1/match``: where the free OSV mirror in Aegis
matches SBOM components against public advisories, this subsystem matches them
against the *premium* feed and enriches every hit with intelligence the public
feed does not carry (exploit maturity, affected functions, reputation, EPSS/KEV,
the alias graph — see ``argus.models.PremiumIntel``).

The matching engine is complete: real per-ecosystem version semantics (``univers``,
the same library the free tier uses) across language and OS-distro ecosystems.
The only thing an integrator wires to go live is the data — return a feed-backed
store from ``argus.feed.default_feed_source``. Until then the default is honest:
``match_components`` returns no hits, so the free OSV match is unaffected.

See ``INTEGRATION.md`` (repo root ``argus/``) for the models and integration steps.
"""
from __future__ import annotations

from argus.matching.ecosystems import (
    osv_base_ecosystem,
    version_class_for,
    version_in_range,
)
from argus.matching.entitlement import (
    AllowAllEntitlement,
    EntitlementChecker,
    default_entitlement_checker,
)
from argus.matching.matcher import PurlCoordinate, match_components, parse_purl
from argus.matching.models import PremiumAdvisoryRecord, VulnerableRange
from argus.matching.store import (
    InMemoryPremiumStore,
    PremiumAdvisoryStore,
    load_premium_store,
)

__all__ = [
    "match_components",
    "parse_purl",
    "PurlCoordinate",
    "osv_base_ecosystem",
    "version_class_for",
    "version_in_range",
    "EntitlementChecker",
    "AllowAllEntitlement",
    "default_entitlement_checker",
    "PremiumAdvisoryRecord",
    "VulnerableRange",
    "PremiumAdvisoryStore",
    "InMemoryPremiumStore",
    "load_premium_store",
]
