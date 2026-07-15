"""Contract tests for the SBOM component diff engine (`diff_sboms`).

Identity is (name, version-stripped purl), so the classification depends on
whether the purl carries the version. These tests lock the happy path (stable
purl -> version_changed), the consequence of version-bearing purls (a bump
reads as add + remove), and the coexisting-versions case where one package
appears in multiple versions on a side (diffed per-version, never a false
"resolved"). The function backs the SBOM diff resolver.
"""
from __future__ import annotations

from src.sbom.diff import _strip_purl_version, diff_sboms


def _sbom(components):
    return {"components": components}


def _c(name, version, purl=None):
    comp = {"name": name, "version": version}
    if purl is not None:
        comp["purl"] = purl
    return comp


def test_added_and_removed():
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash")])
    to = _sbom([_c("react", "18.0", "pkg:npm/react")])
    d = diff_sboms(frm, to)
    assert [c["name"] for c in d.added] == ["react"]
    assert [c["name"] for c in d.removed] == ["lodash"]
    assert d.version_changed == []
    assert d.unchanged_count == 0


def test_version_changed_when_purl_stable():
    # purl WITHOUT an embedded version -> same key across the bump.
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash")])
    to = _sbom([_c("lodash", "2.0", "pkg:npm/lodash")])
    d = diff_sboms(frm, to)
    assert d.added == [] and d.removed == []
    assert d.version_changed == [
        {"name": "lodash", "purl": "pkg:npm/lodash", "type": None, "from_version": "1.0", "to_version": "2.0",
         "from_licenses": [], "to_licenses": []}
    ]
    assert d.unchanged_count == 0


def test_version_changed_carries_component_type():
    # The component ecosystem/type propagates onto the version-bump row so the
    # diff export can populate its ecosystem column (not just added/removed rows).
    frm = _sbom([{"name": "lodash", "version": "1.0", "purl": "pkg:npm/lodash", "type": "library"}])
    to = _sbom([{"name": "lodash", "version": "2.0", "purl": "pkg:npm/lodash", "type": "library"}])
    d = diff_sboms(frm, to)
    assert len(d.version_changed) == 1
    assert d.version_changed[0]["type"] == "library"


def test_unchanged_count():
    same = _c("lodash", "1.0", "pkg:npm/lodash")
    d = diff_sboms(_sbom([dict(same)]), _sbom([dict(same)]))
    assert d.unchanged_count == 1
    assert d.added == [] and d.removed == [] and d.version_changed == []


def test_version_embedded_purl_bump_classifies_as_version_changed():
    # Real CycloneDX purls embed the version; the engine strips it for identity
    # so a pure bump is version_changed (not add+remove). The reported purl is
    # the version-stripped one.
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash@1.0")])
    to = _sbom([_c("lodash", "2.0", "pkg:npm/lodash@2.0")])
    d = diff_sboms(frm, to)
    assert d.added == [] and d.removed == []
    assert d.version_changed == [
        {"name": "lodash", "purl": "pkg:npm/lodash", "type": None, "from_version": "1.0", "to_version": "2.0",
         "from_licenses": [], "to_licenses": []}
    ]


def test_strip_purl_version():
    # Plain version bump separator removed.
    assert _strip_purl_version("pkg:npm/lodash@4.17.21") == "pkg:npm/lodash"
    # No version -> unchanged.
    assert _strip_purl_version("pkg:npm/lodash") == "pkg:npm/lodash"
    # Scoped npm name: the encoded %40 must survive; only the version @ is cut.
    assert _strip_purl_version("pkg:npm/%40babel/core@7.0.0") == "pkg:npm/%40babel/core"
    # Qualifiers (?) and subpath (#) are preserved; version still stripped.
    assert _strip_purl_version("pkg:npm/lodash@4.17.21?arch=x64") == "pkg:npm/lodash?arch=x64"
    assert _strip_purl_version("pkg:golang/x@v1.2.3#sub/dir") == "pkg:golang/x#sub/dir"
    # Non-pkg and empty inputs returned as-is.
    assert _strip_purl_version("") == ""
    assert _strip_purl_version("not-a-purl@1.0") == "not-a-purl@1.0"


def test_version_changed_carries_from_and_to_licenses():
    # A bump that also changes the license must carry both sides' licenses[] so
    # the resolver can flag the compliance change (MIT -> GPL-3.0-only).
    frm = _sbom([{"name": "lib", "version": "1.0", "purl": "pkg:npm/lib",
                  "licenses": [{"license": {"id": "MIT"}}]}])
    to = _sbom([{"name": "lib", "version": "2.0", "purl": "pkg:npm/lib",
                 "licenses": [{"license": {"id": "GPL-3.0-only"}}]}])
    vc = diff_sboms(frm, to).version_changed
    assert vc[0]["from_licenses"] == [{"license": {"id": "MIT"}}]
    assert vc[0]["to_licenses"] == [{"license": {"id": "GPL-3.0-only"}}]


def test_purl_less_components_key_on_name():
    frm = _sbom([_c("internal-lib", "1.0")])  # no purl -> (name, "")
    to = _sbom([_c("internal-lib", "2.0")])
    d = diff_sboms(frm, to)
    assert d.version_changed == [
        {"name": "internal-lib", "purl": "", "type": None, "from_version": "1.0", "to_version": "2.0",
         "from_licenses": [], "to_licenses": []}
    ]


def test_same_name_different_purl_are_distinct():
    # Same package name across ecosystems -> distinct identities.
    frm = _sbom([_c("requests", "1.0", "pkg:pypi/requests")])
    to = _sbom([_c("requests", "1.0", "pkg:npm/requests")])
    d = diff_sboms(frm, to)
    assert len(d.added) == 1 and d.added[0]["purl"] == "pkg:npm/requests"
    assert len(d.removed) == 1 and d.removed[0]["purl"] == "pkg:pypi/requests"


def test_empty_or_missing_components():
    assert diff_sboms({}, {}).unchanged_count == 0
    d = diff_sboms({}, _sbom([_c("x", "1.0", "pkg:npm/x")]))
    assert len(d.added) == 1 and d.removed == []


def test_non_dict_or_malformed_sides_contribute_no_components():
    # A corrupt / non-CycloneDX side (a JSON list, a non-list components value,
    # or non-dict component entries) must not raise — it contributes nothing.
    valid = _sbom([_c("x", "1.0", "pkg:npm/x")])
    assert diff_sboms(["not", "a", "dict"], valid).added[0]["name"] == "x"  # type: ignore[arg-type]
    assert diff_sboms({"components": "not-a-list"}, valid).added[0]["name"] == "x"
    mixed = {"components": ["junk", _c("x", "1.0", "pkg:npm/x"), 42]}
    assert diff_sboms(mixed, mixed).unchanged_count == 1
    assert diff_sboms(valid, ["not", "a", "dict"]).removed[0]["name"] == "x"  # type: ignore[arg-type]


# ── Coexisting versions of one package (version-stripped identity) ──────────
#
# A package can legitimately appear in two versions in one SBOM (npm hoisting,
# stacked container layers). They share a version-stripped identity, so a naive
# last-wins collapse would drop the shadowed copy and could report a vuln
# "resolved" when a vulnerable version is still present. These lock the
# per-version diff that prevents that.


def test_added_version_alongside_existing_is_not_a_false_resolve():
    # from: lodash@1.0 (vulnerable). to: BOTH lodash@1.0 AND lodash@2.0.
    # The vulnerable 1.0 still ships — this must read as "added 2.0", with 1.0
    # unchanged, NOT "version_changed 1.0->2.0" (which the overlay would render
    # as a resolved advisory).
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash")])
    to = _sbom([_c("lodash", "1.0", "pkg:npm/lodash"), _c("lodash", "2.0", "pkg:npm/lodash")])
    d = diff_sboms(frm, to)
    assert d.version_changed == []
    assert [c["version"] for c in d.added] == ["2.0"]
    assert d.removed == []
    assert d.unchanged_count == 1  # 1.0 is still present


def test_removed_one_of_two_coexisting_versions():
    # from: lodash@1.0 AND 2.0. to: only 2.0. → 1.0 removed, 2.0 unchanged.
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash"), _c("lodash", "2.0", "pkg:npm/lodash")])
    to = _sbom([_c("lodash", "2.0", "pkg:npm/lodash")])
    d = diff_sboms(frm, to)
    assert d.version_changed == []
    assert [c["version"] for c in d.removed] == ["1.0"]
    assert d.added == []
    assert d.unchanged_count == 1


def test_disjoint_coexisting_versions_are_add_plus_remove_not_change():
    # from: 1.0 AND 2.0. to: 3.0 AND 4.0. No clean pairing → all add/remove.
    frm = _sbom([_c("p", "1.0", "pkg:npm/p"), _c("p", "2.0", "pkg:npm/p")])
    to = _sbom([_c("p", "3.0", "pkg:npm/p"), _c("p", "4.0", "pkg:npm/p")])
    d = diff_sboms(frm, to)
    assert d.version_changed == []
    assert sorted(c["version"] for c in d.added) == ["3.0", "4.0"]
    assert sorted(c["version"] for c in d.removed) == ["1.0", "2.0"]
    assert d.unchanged_count == 0


def test_single_version_bump_still_reads_as_version_changed():
    # Regression guard: the ordinary 1<->1 bump must keep the version_changed
    # classification (the deliberate #1056 behavior), not become add+remove.
    frm = _sbom([_c("lodash", "1.0", "pkg:npm/lodash")])
    to = _sbom([_c("lodash", "2.0", "pkg:npm/lodash")])
    d = diff_sboms(frm, to)
    assert d.added == [] and d.removed == []
    assert [(v["from_version"], v["to_version"]) for v in d.version_changed] == [("1.0", "2.0")]
