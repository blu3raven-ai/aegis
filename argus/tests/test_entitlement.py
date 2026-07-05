"""Premium entitlement gating in the matcher."""
from __future__ import annotations

from argus.matching import (
    AllowAllEntitlement,
    InMemoryPremiumStore,
    default_entitlement_checker,
    match_components,
)
from argus.matching.models import PremiumAdvisoryRecord, VulnerableRange
from argus.models import MatchAdvisory, MatchComponent


def _store():
    return InMemoryPremiumStore(
        [
            PremiumAdvisoryRecord(
                ecosystem="PyPI",
                package="django",
                advisory=MatchAdvisory(id="GHSA-test-test-test", severity="high"),
                ranges=[VulnerableRange(introduced="4.0", fixed="4.2.1")],
            )
        ]
    )


_COMPONENT = MatchComponent(purl="pkg:pypi/django@4.2.0", version="4.2.0")


class _DenyAll:
    def is_entitled(self, org_id: str, surface: str) -> bool:
        return False


def test_default_checker_allows_all():
    assert default_entitlement_checker().is_entitled("any-org", "deps") is True


def test_entitled_org_gets_premium_hits():
    hits = match_components(
        "deps", [_COMPONENT], org_id="acme-org", store=_store(),
        entitlement=AllowAllEntitlement(),
    )
    assert len(hits) == 1


def test_unentitled_org_gets_empty_response():
    hits = match_components(
        "deps", [_COMPONENT], org_id="acme-org", store=_store(), entitlement=_DenyAll()
    )
    assert hits == []


def test_no_org_skips_entitlement_check():
    # Direct/unauthenticated callers (no org) are not entitlement-gated.
    hits = match_components("deps", [_COMPONENT], store=_store())
    assert len(hits) == 1


def test_entitlement_short_circuits_before_store():
    # A denied org never touches the store (passing a store that would explode
    # proves the gate runs first).
    class _Boom:
        def advisories_for(self, ecosystem, package):
            raise AssertionError("store must not be queried for an unentitled org")

    hits = match_components(
        "deps", [_COMPONENT], org_id="acme-org", store=_Boom(), entitlement=_DenyAll()
    )
    assert hits == []
