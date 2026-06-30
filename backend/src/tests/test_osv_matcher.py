"""Unit tests for backend-native OSV matching.

Covers the keystone pieces:
  - version_in_osv_range — OSV interval semantics across ecosystems
  - parse_purl / ecosystem normalization — purl type+namespace -> OSV ecosystem
  - _flatten_ranges — multi-interval pairing + explicit-versions fallback
  - match_components — end-to-end against a seeded OSV mirror (real test DB)
"""
from __future__ import annotations

import pytest
from univers import versions as V

from src.osv.ecosystems import (
    osv_base_ecosystem,
    osv_ecosystem_base,
    version_class_for,
)
from src.osv.matcher import (
    ComponentRef,
    match_components,
    parse_purl,
    version_in_osv_range,
)
from src.osv.store import OsvStore, _flatten_ranges


# ── version_in_osv_range ───────────────────────────────────────────────────

def test_range_introduced_zero_fixed_excludes_at_and_after_fix():
    # lodash < 4.17.21 vulnerable
    assert version_in_osv_range("4.17.20", "0", "4.17.21", None, V.SemverVersion)
    assert not version_in_osv_range("4.17.21", "0", "4.17.21", None, V.SemverVersion)
    assert not version_in_osv_range("4.18.0", "0", "4.17.21", None, V.SemverVersion)


def test_range_introduced_lower_bound_excludes_below():
    assert not version_in_osv_range("1.9.0", "2.0.0", "2.5.0", None, V.SemverVersion)
    assert version_in_osv_range("2.0.0", "2.0.0", "2.5.0", None, V.SemverVersion)
    assert version_in_osv_range("2.4.9", "2.0.0", "2.5.0", None, V.SemverVersion)
    assert not version_in_osv_range("2.5.0", "2.0.0", "2.5.0", None, V.SemverVersion)


def test_range_last_affected_inclusive_upper_bound():
    assert version_in_osv_range("1.2.3", "0", None, "1.2.3", V.SemverVersion)
    assert not version_in_osv_range("1.2.4", "0", None, "1.2.3", V.SemverVersion)


def test_range_open_ended_introduced_only_matches_everything_after():
    assert version_in_osv_range("9.9.9", "1.0.0", None, None, V.SemverVersion)
    assert not version_in_osv_range("0.9.0", "1.0.0", None, None, V.SemverVersion)


def test_pypi_pep440_ordering_not_lexical():
    # 1.10 > 1.9 numerically (lexical would say otherwise)
    assert version_in_osv_range("1.9", "0", "1.10", None, V.PypiVersion)
    assert not version_in_osv_range("1.10", "0", "1.10", None, V.PypiVersion)


def test_debian_dpkg_epoch_and_revision_ordering():
    assert version_in_osv_range(
        "1.1.1n-0+deb11u4", "0", "1.1.1n-0+deb11u5", None, V.DebianVersion
    )
    assert not version_in_osv_range(
        "1.1.1n-0+deb11u5", "0", "1.1.1n-0+deb11u5", None, V.DebianVersion
    )


def test_rpm_release_ordering():
    assert version_in_osv_range("1.0-1.el8", "0", "1.0-2.el8", None, V.RpmVersion)
    assert not version_in_osv_range("1.0-2.el8", "0", "1.0-2.el8", None, V.RpmVersion)


def test_alpine_revision_ordering():
    assert version_in_osv_range("1.2.3-r0", "0", "1.2.3-r1", None, V.AlpineLinuxVersion)
    assert not version_in_osv_range("1.2.3-r1", "0", "1.2.3-r1", None, V.AlpineLinuxVersion)


def test_unparseable_version_fails_closed_without_raising():
    assert version_in_osv_range("not-a-version", "0", "1.0.0", None, V.SemverVersion) is False


# ── parse_purl / ecosystem normalization ───────────────────────────────────

def test_parse_purl_language_no_namespace():
    assert parse_purl("pkg:npm/lodash@4.17.20") == ("npm", None)
    assert parse_purl("pkg:pypi/requests@2.31.0") == ("pypi", None)


def test_parse_purl_distro_with_namespace():
    assert parse_purl("pkg:deb/debian/openssl@1.1.1n?distro=debian-11") == ("deb", "debian")
    assert parse_purl("pkg:apk/alpine/musl@1.2.3-r0") == ("apk", "alpine")
    assert parse_purl("pkg:rpm/rocky/zlib@1.2.11") == ("rpm", "rocky")


def test_parse_purl_scoped_npm_namespace():
    # scoped npm names look like a namespace but matching uses the name directly
    t, ns = parse_purl("pkg:npm/@babel/core@7.0.0")
    assert t == "npm"


def test_parse_purl_empty_or_malformed():
    assert parse_purl("") == ("", None)
    assert parse_purl("lodash@4.17.20") == ("", None)


def test_osv_base_ecosystem_language_casing():
    assert osv_base_ecosystem("pypi") == "PyPI"
    assert osv_base_ecosystem("cargo") == "crates.io"
    assert osv_base_ecosystem("gem") == "RubyGems"
    assert osv_base_ecosystem("nuget") == "NuGet"
    assert osv_base_ecosystem("golang") == "Go"


def test_osv_base_ecosystem_distro_namespace_disambiguation():
    assert osv_base_ecosystem("deb", "debian") == "Debian"
    assert osv_base_ecosystem("deb", "ubuntu") == "Ubuntu"
    assert osv_base_ecosystem("apk", "alpine") == "Alpine"
    assert osv_base_ecosystem("apk", "wolfi") == "Wolfi"
    assert osv_base_ecosystem("rpm", "rocky") == "Rocky Linux"


def test_osv_base_ecosystem_unknown_returns_none():
    assert osv_base_ecosystem("cocoapods") is None


def test_version_class_tolerates_release_suffix():
    assert version_class_for("Debian:11") is V.DebianVersion
    assert version_class_for("Alpine:v3.18") is V.AlpineLinuxVersion
    assert osv_ecosystem_base("Ubuntu:22.04:LTS") == "Ubuntu"


# ── _flatten_ranges ─────────────────────────────────────────────────────────

def test_flatten_multiple_intervals_in_one_range():
    adv = {
        "id": "GHSA-multi",
        "affected": [{
            "package": {"name": "pkg", "ecosystem": "npm"},
            "ranges": [{
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"}, {"fixed": "1.5.0"},
                    {"introduced": "2.0.0"}, {"fixed": "2.3.0"},
                ],
            }],
        }],
    }
    rows = _flatten_ranges(adv, "npm")
    intervals = {(r["range_introduced"], r["range_fixed"]) for r in rows}
    assert intervals == {("1.0.0", "1.5.0"), ("2.0.0", "2.3.0")}


def test_flatten_open_ended_trailing_interval():
    adv = {
        "id": "GHSA-open",
        "affected": [{
            "package": {"name": "pkg", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.0.0"}]}],
        }],
    }
    rows = _flatten_ranges(adv, "npm")
    assert rows == [{
        "package_name": "pkg", "ecosystem": "npm",
        "range_introduced": "3.0.0", "range_fixed": None, "range_last_affected": None,
    }]


def test_flatten_explicit_versions_when_no_ranges():
    adv = {
        "id": "GHSA-explicit",
        "affected": [{
            "package": {"name": "pkg", "ecosystem": "PyPI"},
            "versions": ["1.0.0", "1.0.1"],
        }],
    }
    rows = _flatten_ranges(adv, "PyPI")
    pts = {(r["range_introduced"], r["range_last_affected"]) for r in rows}
    assert pts == {("1.0.0", "1.0.0"), ("1.0.1", "1.0.1")}


def test_flatten_prefers_ranges_over_versions():
    adv = {
        "id": "GHSA-both",
        "affected": [{
            "package": {"name": "pkg", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            "versions": ["1.0.0", "1.5.0"],
        }],
    }
    rows = _flatten_ranges(adv, "npm")
    assert len(rows) == 1
    assert rows[0]["range_fixed"] == "2.0.0"


# ── match_components (DB-backed) ─────────────────────────────────────────────

def _adv(adv_id, ecosystem, name, introduced, fixed):
    return {
        "id": adv_id,
        "summary": f"{adv_id}",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "published": "2026-06-01T00:00:00Z",
        "modified": "2026-06-15T00:00:00Z",
        "affected": [{
            "package": {"name": name, "ecosystem": ecosystem},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}],
        }],
    }


@pytest.mark.asyncio
async def test_match_components_end_to_end(monkeypatch):
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from src.db.engine import DATABASE_URL

    # Remove any stale advisory rows for the exact packages under test so
    # other tests' DB writes don't produce phantom matches here.
    _TEST_PACKAGES = ("lodash", "requests", "openssl", "leftpad")
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text("DELETE FROM osv_vulnerable_ranges WHERE package_name = ANY(:pkgs)"),
            {"pkgs": list(_TEST_PACKAGES)},
        )
        await session.commit()
    await engine.dispose()

    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    await store.upsert_advisories(
        [
            _adv("GHSA-lodash", "npm", "lodash", "0", "4.17.21"),
            _adv("PYSEC-req", "PyPI", "requests", "0", "2.31.0"),
            _adv("DEB-openssl", "Debian:11", "openssl", "0", "1.1.1n-0+deb11u5"),
        ],
        ecosystem="npm",
    )

    comps = [
        ComponentRef(name="lodash", version="4.17.20", purl_type="npm"),
        ComponentRef(name="lodash", version="4.17.21", purl_type="npm"),       # patched
        ComponentRef(name="requests", version="2.30.0", purl_type="pypi"),
        ComponentRef(name="openssl", version="1.1.1n-0+deb11u4", purl_type="deb", namespace="debian"),
        ComponentRef(name="leftpad", version="1.0.0", purl_type="npm"),        # no advisory
    ]

    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            matched = await match_components(session, comps)
    finally:
        await engine.dispose()

    hit = {c.name: [m.advisory_id for m in ms] for c, ms in matched.items()}
    assert hit.get("lodash") == ["GHSA-lodash"]   # only the 4.17.20 component
    assert hit.get("requests") == ["PYSEC-req"]
    assert hit.get("openssl") == ["DEB-openssl"]
    assert "leftpad" not in hit
    # the patched lodash@4.17.21 produced no match
    assert all(c.version != "4.17.21" for c in matched)


# ── Distro-release extraction + mapping (pure) ──────────────────────────────


def test_parse_purl_distro():
    from src.osv.matcher import parse_purl_distro
    assert parse_purl_distro("pkg:deb/debian/openssl@1.1.1n?distro=debian-11") == "debian-11"
    assert parse_purl_distro("pkg:apk/alpine/musl@1.2?arch=x86_64&distro=alpine-3.18") == "alpine-3.18"
    assert parse_purl_distro("pkg:npm/lodash@4.17.21") is None
    assert parse_purl_distro("pkg:deb/debian/openssl@1.1.1n?arch=amd64") is None


def test_osv_release_ecosystem_maps_only_verbatim_distros():
    from src.osv.ecosystems import osv_release_ecosystem
    # Debian is the only verbatim-safe distro: OSV uses plain "Debian:11".
    assert osv_release_ecosystem("debian-11") == "Debian:11"
    # Ubuntu deliberately does NOT map: OSV suffixes LTS releases as
    # "Ubuntu:22.04:LTS", so exact-equality narrowing to "Ubuntu:22.04" would
    # drop every LTS advisory (false negative). Falls back to base matching.
    assert osv_release_ecosystem("ubuntu-22.04") is None
    # Alpine (v-prefixed in OSV), RPM family, codenames, and missing/garbage
    # releases also DON'T map → caller falls back to base matching.
    assert osv_release_ecosystem("alpine-3.18") is None
    assert osv_release_ecosystem("debian-bookworm") is None
    assert osv_release_ecosystem("rocky-8") is None
    assert osv_release_ecosystem(None) is None
    assert osv_release_ecosystem("debian-") is None


@pytest.mark.asyncio
async def test_release_narrowing_excludes_other_releases(monkeypatch):
    """A component pinned to Debian 11 must not be flagged by a Debian 12-only
    advisory whose range happens to include its version — while a component with
    no mapped release still matches every release (no advisory dropped)."""
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
    from src.db.engine import DATABASE_URL

    pkg = "opensslrel"
    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text("DELETE FROM osv_vulnerable_ranges WHERE package_name = :p"), {"p": pkg}
        )
        await session.commit()
    await engine.dispose()

    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)
    # Both releases' advisories have ranges that include 1.1.1n-0+deb11u4
    # (deb11u4 < deb11u5 and deb11u4 < deb12u1), so without narrowing the
    # deb11 component would match BOTH — the false positive this fixes.
    await store.upsert_advisories(
        [
            _adv("DEB11", "Debian:11", pkg, "0", "1.1.1n-0+deb11u5"),
            _adv("DEB12", "Debian:12", pkg, "0", "1.1.1n-0+deb12u1"),
        ],
        ecosystem="npm",
    )

    comps = [
        ComponentRef(name=pkg, version="1.1.1n-0+deb11u4", purl_type="deb",
                     namespace="debian", release_ecosystem="Debian:11"),
        ComponentRef(name=pkg, version="1.1.1n-0+deb11u4", purl_type="deb",
                     namespace="debian"),  # no mapped release → matches both
    ]

    engine = create_async_engine(DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as session:
            matched = await match_components(session, comps)
    finally:
        await engine.dispose()

    by_release = {c.release_ecosystem: sorted(m.advisory_id for m in ms) for c, ms in matched.items()}
    # Pinned to Debian 11 → only the Debian:11 advisory.
    assert by_release.get("Debian:11") == ["DEB11"]
    # No mapped release → both (fallback, nothing dropped).
    assert by_release.get(None) == ["DEB11", "DEB12"]
