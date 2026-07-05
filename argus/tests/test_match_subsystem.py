"""Tests for the premium dependency-match subsystem (argus.matching)."""
from __future__ import annotations

from pathlib import Path

import pytest

from argus.matching import (
    InMemoryPremiumStore,
    load_premium_store,
    match_components,
    parse_purl,
)
from argus.matching.models import PremiumAdvisoryRecord, VulnerableRange
from argus.models import MatchAdvisory, MatchComponent

_SAMPLE = Path(__file__).resolve().parents[1] / "matching" / "sample_advisories.json"


def _record(introduced="1.0.0", fixed="1.2.3", last_affected=None):
    return PremiumAdvisoryRecord(
        ecosystem="pypi",
        package="example-pkg",
        advisory=MatchAdvisory(id="GHSA-aaaa-bbbb-cccc", severity="high"),
        ranges=[
            VulnerableRange(introduced=introduced, fixed=fixed, last_affected=last_affected)
        ],
        intel={"exploit_maturity": "poc", "kev_listed": True, "epss_score": 0.42},
    )


@pytest.mark.parametrize(
    "purl,expected",
    [
        ("pkg:pypi/django@4.2.0", ("pypi", None, "django")),
        ("pkg:npm/%40scope/pkg@1.0.0", ("npm", "@scope", "pkg")),
        ("pkg:golang/github.com/foo/bar@v1.2.3", ("golang", "github.com/foo", "bar")),
        ("pkg:pypi/flask@2.0.0?arch=x86#sub", ("pypi", None, "flask")),
        ("pkg:deb/debian/openssl@1.1.1", ("deb", "debian", "openssl")),
        ("not-a-purl", (None, None, None)),
        (None, (None, None, None)),
    ],
)
def test_parse_purl(purl, expected):
    coord = parse_purl(purl)
    assert (coord.purl_type, coord.namespace, coord.name) == expected


def test_default_store_is_empty():
    # Honest placeholder: nothing is served until a real feed is wired.
    assert load_premium_store().advisories_for("pypi", "example-pkg") == []


def test_match_with_default_store_yields_no_hits():
    component = MatchComponent(purl="pkg:pypi/example-pkg@1.1.0", version="1.1.0")
    assert match_components("deps", [component]) == []


def test_match_in_range_emits_item_with_premium_intel():
    store = InMemoryPremiumStore([_record()])
    component = MatchComponent(purl="pkg:pypi/example-pkg@1.1.0", version="1.1.0")

    hits = match_components("deps", [component], store=store)

    assert len(hits) == 1
    hit = hits[0]
    assert hit.package.name == "example-pkg"
    assert hit.package.ecosystem == "pypi"
    assert hit.version == "1.1.0"
    assert hit.advisory.id == "GHSA-aaaa-bbbb-cccc"
    # The premium delta rides along.
    assert hit.intel is not None
    assert hit.intel.exploit_maturity == "poc"
    assert hit.intel.kev_listed is True
    assert hit.intel.epss_score == 0.42


def test_match_out_of_range_is_skipped():
    store = InMemoryPremiumStore([_record(introduced="1.0.0", fixed="1.2.3")])
    patched = MatchComponent(purl="pkg:pypi/example-pkg@1.2.3", version="1.2.3")
    below = MatchComponent(purl="pkg:pypi/example-pkg@0.9.0", version="0.9.0")

    assert match_components("deps", [patched, below], store=store) == []


def test_match_keys_are_case_insensitive():
    store = InMemoryPremiumStore([_record()])
    component = MatchComponent(purl="pkg:PyPI/Example-Pkg@1.1.0", version="1.1.0")
    assert len(match_components("deps", [component], store=store)) == 1


def test_sample_file_loads_and_matches():
    store = InMemoryPremiumStore.from_json_file(_SAMPLE)
    component = MatchComponent(purl="pkg:pypi/example-pkg@1.1.0", version="1.1.0")

    hits = match_components("deps", [component], store=store)

    assert len(hits) == 1
    assert hits[0].intel.aliases == ["CVE-2024-00000", "GHSA-aaaa-bbbb-cccc"]
