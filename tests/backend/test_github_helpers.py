"""Pure-logic coverage for shared/github.py — Link-header pagination, purl parsing,
ecosystem normalization, and header/record helpers."""
from __future__ import annotations

from src.shared.github import (
    _as_record,
    _github_headers,
    _normalize_ecosystem,
    _package_key,
    _parse_next_link,
    _parse_purl,
)


def test_parse_next_link():
    hdr = '<https://api.github.com/x?page=2>; rel="next", <https://api.github.com/x?page=9>; rel="last"'
    assert _parse_next_link(hdr) == "https://api.github.com/x?page=2"
    assert _parse_next_link('<https://api.github.com/x?page=9>; rel="last"') is None  # no next
    assert _parse_next_link(None) is None
    assert _parse_next_link("") is None


def test_github_headers():
    h = _github_headers("tok123")
    assert h["Authorization"] == "Bearer tok123"
    assert h["Accept"] == "application/vnd.github+json"
    assert h["X-GitHub-Api-Version"] == "2022-11-28"


def test_normalize_ecosystem_maps_and_lowercases():
    assert _normalize_ecosystem("PyPI") == "pip"
    assert _normalize_ecosystem("gem") == "rubygems"
    assert _normalize_ecosystem("golang") == "go"
    assert _normalize_ecosystem("NPM") == "npm"  # unmapped → lowercased


def test_package_key():
    assert _package_key("pypi", "Requests") == "pip:requests"


def test_parse_purl_extracts_ecosystem_and_name():
    assert _parse_purl("pkg:npm/left-pad@1.3.0") == {"ecosystem": "npm", "name": "left-pad"}
    # pypi type is normalized; version + qualifiers stripped
    assert _parse_purl("pkg:pypi/requests@2.0?arch=x") == {"ecosystem": "pip", "name": "requests"}
    # no version separator
    assert _parse_purl("pkg:gem/rails") == {"ecosystem": "rubygems", "name": "rails"}


def test_parse_purl_rejects_non_purl():
    assert _parse_purl("npm/left-pad") is None      # no pkg: prefix
    assert _parse_purl("pkg:npm") is None            # no slash
    assert _parse_purl("") is None


def test_as_record():
    assert _as_record({"a": 1}) == {"a": 1}
    assert _as_record("nope") == {}
    assert _as_record(None) == {}
