"""Unit tests for the SBOM diff engine — Phase 37.

Pure function tests; no I/O, no database, no network.
"""
from __future__ import annotations

import pytest

from src.sbom.diff import diff_sboms, ComponentDiff


# ── fixtures ──────────────────────────────────────────────────────────────────

def _sbom(*components: dict) -> dict:
    """Minimal CycloneDX JSON SBOM with the given components list."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": list(components),
    }


def _pkg(name: str, version: str, purl: str | None = None) -> dict:
    c: dict = {"name": name, "version": version}
    if purl is not None:
        c["purl"] = purl
    return c


AXIOS_OLD = _pkg("axios", "1.3.0", "pkg:npm/axios@1.3.0")
AXIOS_NEW = _pkg("axios", "1.6.0", "pkg:npm/axios@1.6.0")
LODASH = _pkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
REACT = _pkg("react", "18.2.0", "pkg:npm/react@18.2.0")
EXPRESS_OLD = _pkg("express", "4.18.0", "pkg:npm/express@4.18.0")
EXPRESS_NEW = _pkg("express", "4.18.2", "pkg:npm/express@4.18.2")


# ── nothing changed ───────────────────────────────────────────────────────────

def test_identical_sboms_no_diff():
    sbom = _sbom(AXIOS_OLD, LODASH)
    result = diff_sboms(sbom, sbom)

    assert result.added == []
    assert result.removed == []
    assert result.version_changed == []
    assert result.unchanged_count == 2


def test_both_empty_sboms():
    result = diff_sboms(_sbom(), _sbom())

    assert result.added == []
    assert result.removed == []
    assert result.version_changed == []
    assert result.unchanged_count == 0


# ── added components ──────────────────────────────────────────────────────────

def test_added_single_component():
    from_sbom = _sbom(LODASH)
    to_sbom = _sbom(LODASH, REACT)
    result = diff_sboms(from_sbom, to_sbom)

    assert len(result.added) == 1
    assert result.added[0]["name"] == "react"
    assert result.removed == []
    assert result.version_changed == []
    assert result.unchanged_count == 1


def test_added_multiple_components():
    from_sbom = _sbom(LODASH)
    to_sbom = _sbom(LODASH, REACT, AXIOS_OLD)
    result = diff_sboms(from_sbom, to_sbom)

    assert len(result.added) == 2
    added_names = {c["name"] for c in result.added}
    assert added_names == {"react", "axios"}
    assert result.unchanged_count == 1


def test_added_from_empty_sbom():
    result = diff_sboms(_sbom(), _sbom(LODASH, REACT))

    assert len(result.added) == 2
    assert result.removed == []
    assert result.unchanged_count == 0


# ── removed components ────────────────────────────────────────────────────────

def test_removed_single_component():
    from_sbom = _sbom(LODASH, REACT)
    to_sbom = _sbom(LODASH)
    result = diff_sboms(from_sbom, to_sbom)

    assert len(result.removed) == 1
    assert result.removed[0]["name"] == "react"
    assert result.added == []
    assert result.unchanged_count == 1


def test_removed_to_empty_sbom():
    result = diff_sboms(_sbom(LODASH, REACT), _sbom())

    assert len(result.removed) == 2
    assert result.added == []
    assert result.unchanged_count == 0


# ── version changed ───────────────────────────────────────────────────────────

def test_version_changed_single():
    """Version bump on same package name shows up in version_changed, not add/remove."""
    # axios is identified by (name, purl); the purl differs between versions,
    # so we use a purl-less component to test the name-only path.
    old_axios = _pkg("axios", "1.3.0")
    new_axios = _pkg("axios", "1.6.0")
    result = diff_sboms(_sbom(old_axios), _sbom(new_axios))

    assert result.added == []
    assert result.removed == []
    assert len(result.version_changed) == 1
    change = result.version_changed[0]
    assert change["name"] == "axios"
    assert change["from_version"] == "1.3.0"
    assert change["to_version"] == "1.6.0"
    assert result.unchanged_count == 0


def test_version_changed_multiple():
    old_express = _pkg("express", "4.18.0")
    new_express = _pkg("express", "4.18.2")
    old_webpack = _pkg("webpack", "5.78.0")
    new_webpack = _pkg("webpack", "5.79.0")

    result = diff_sboms(
        _sbom(old_express, old_webpack, LODASH),
        _sbom(new_express, new_webpack, LODASH),
    )

    assert len(result.version_changed) == 2
    names = {c["name"] for c in result.version_changed}
    assert names == {"express", "webpack"}
    assert result.unchanged_count == 1


# ── mixed scenario ────────────────────────────────────────────────────────────

def test_mixed_changes():
    """Combination of add, remove, version change, and unchanged."""
    old_express = _pkg("express", "4.18.0")
    new_express = _pkg("express", "4.18.2")
    jquery = _pkg("jquery", "3.6.0")

    from_sbom = _sbom(old_express, jquery, LODASH)
    to_sbom = _sbom(new_express, LODASH, REACT)
    result = diff_sboms(from_sbom, to_sbom)

    assert len(result.added) == 1
    assert result.added[0]["name"] == "react"

    assert len(result.removed) == 1
    assert result.removed[0]["name"] == "jquery"

    assert len(result.version_changed) == 1
    assert result.version_changed[0]["name"] == "express"
    assert result.version_changed[0]["from_version"] == "4.18.0"
    assert result.version_changed[0]["to_version"] == "4.18.2"

    assert result.unchanged_count == 1  # lodash


# ── purl-based identity ───────────────────────────────────────────────────────

def test_purl_distinguishes_same_name_different_ecosystem():
    """Two packages with the same name but different purls are treated as distinct."""
    npm_react = _pkg("react", "18.2.0", "pkg:npm/react@18.2.0")
    pypi_react = _pkg("react", "1.0.0", "pkg:pypi/react@1.0.0")

    result = diff_sboms(_sbom(npm_react), _sbom(pypi_react))

    # Different (name, purl) keys → one added, one removed
    assert len(result.added) == 1
    assert len(result.removed) == 1
    assert result.version_changed == []


def test_version_changed_carries_purl():
    old_pkg = _pkg("mylib", "1.0.0", None)
    new_pkg = _pkg("mylib", "2.0.0", None)
    result = diff_sboms(_sbom(old_pkg), _sbom(new_pkg))

    assert len(result.version_changed) == 1
    assert result.version_changed[0]["purl"] == ""


# ── components missing optional fields ────────────────────────────────────────

def test_component_missing_version_counts_as_unchanged_when_same():
    c1 = {"name": "no-version-pkg"}
    result = diff_sboms(_sbom(c1), _sbom(c1))

    assert result.unchanged_count == 1
    assert result.version_changed == []


def test_component_version_none_vs_string():
    no_ver = {"name": "pkg"}
    has_ver = {"name": "pkg", "version": "1.0.0"}
    result = diff_sboms(_sbom(no_ver), _sbom(has_ver))

    assert len(result.version_changed) == 1
    assert result.version_changed[0]["from_version"] is None
    assert result.version_changed[0]["to_version"] == "1.0.0"


# ── return type ───────────────────────────────────────────────────────────────

def test_returns_component_diff_dataclass():
    result = diff_sboms(_sbom(LODASH), _sbom(REACT))
    assert isinstance(result, ComponentDiff)
