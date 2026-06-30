"""Real per-ecosystem version semantics + coordinate resolution in the matcher."""
from __future__ import annotations

import pytest

from argus.matching import (
    InMemoryPremiumStore,
    match_components,
    osv_base_ecosystem,
    version_class_for,
)
from argus.matching.matcher import _canonical_name, _coordinate, parse_purl
from argus.matching.models import PremiumAdvisoryRecord, VulnerableRange
from argus.models import MatchAdvisory, MatchComponent


def _record(ecosystem, package, introduced="0", fixed=None, last_affected=None):
    return PremiumAdvisoryRecord(
        ecosystem=ecosystem,
        package=package,
        advisory=MatchAdvisory(id="GHSA-test-test-test", severity="high"),
        ranges=[VulnerableRange(introduced=introduced, fixed=fixed, last_affected=last_affected)],
    )


@pytest.mark.parametrize(
    "purl_type,namespace,expected",
    [
        ("pypi", None, "PyPI"),
        ("npm", None, "npm"),
        ("golang", None, "Go"),
        ("maven", None, "Maven"),
        ("cargo", None, "crates.io"),
        ("deb", "ubuntu", "Ubuntu"),
        ("deb", "debian", "Debian"),
        ("apk", "alpine", "Alpine"),
        ("rpm", "rocky", "Rocky Linux"),
        ("unknowntype", None, None),
    ],
)
def test_osv_base_ecosystem(purl_type, namespace, expected):
    assert osv_base_ecosystem(purl_type, namespace) == expected


def test_version_class_resolves_per_ecosystem():
    assert version_class_for("PyPI") is not None
    assert version_class_for("npm") is not None
    assert version_class_for("Debian:11") is not None  # release suffix tolerated
    assert version_class_for("NotAnEcosystem") is None


@pytest.mark.parametrize(
    "purl,expected_name",
    [
        ("pkg:npm/%40babel/core@7.0.0", "@babel/core"),
        ("pkg:npm/lodash@4.17.20", "lodash"),
        ("pkg:maven/com.google.guava/guava@31.0", "com.google.guava:guava"),
        ("pkg:golang/github.com/foo/bar@v1.2.3", "github.com/foo/bar"),
        ("pkg:deb/debian/openssl@1.1.1", "openssl"),
    ],
)
def test_canonical_name(purl, expected_name):
    assert _canonical_name(parse_purl(purl)) == expected_name


def test_npm_semver_range_match():
    # SemVer: 4.17.20 is < 4.17.21, so it is affected.
    store = InMemoryPremiumStore([_record("npm", "lodash", introduced="4.0.0", fixed="4.17.21")])
    comp = MatchComponent(purl="pkg:npm/lodash@4.17.20", version="4.17.20")
    assert len(match_components("deps", [comp], store=store)) == 1

    fixed = MatchComponent(purl="pkg:npm/lodash@4.17.21", version="4.17.21")
    assert match_components("deps", [fixed], store=store) == []


def test_debian_version_semantics():
    # Debian epoch/revision ordering: 1.1.1n-0+deb10u3 < 1.1.1n-0+deb10u4.
    store = InMemoryPremiumStore(
        [_record("Debian", "openssl", introduced="0", fixed="1.1.1n-0+deb10u4")]
    )
    vuln = MatchComponent(
        purl="pkg:deb/debian/openssl@1.1.1n-0+deb10u3?distro=debian-10",
        version="1.1.1n-0+deb10u3",
    )
    assert len(match_components("deps", [vuln], store=store)) == 1


def test_explicit_coordinate_overrides_purl():
    # Integrator sends canonical name + OSV ecosystem; purl is absent.
    store = InMemoryPremiumStore([_record("PyPI", "django", introduced="4.0", fixed="4.2.1")])
    comp = MatchComponent(version="4.2.0", name="django", ecosystem="PyPI")
    assert _coordinate(comp) == ("PyPI", "django")
    assert len(match_components("deps", [comp], store=store)) == 1


def test_unmapped_ecosystem_is_skipped():
    store = InMemoryPremiumStore([_record("npm", "lodash", fixed="9.9.9")])
    comp = MatchComponent(purl="pkg:weirdtype/thing@1.0.0", version="1.0.0")
    assert match_components("deps", [comp], store=store) == []


def test_unparseable_version_does_not_crash():
    store = InMemoryPremiumStore([_record("PyPI", "django", fixed="4.2.1")])
    comp = MatchComponent(purl="pkg:pypi/django@not-a-version", version="not-a-version")
    # Fails closed for that comparison rather than raising.
    assert match_components("deps", [comp], store=store) == []
