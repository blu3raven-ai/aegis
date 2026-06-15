"""Tests for runner.scanners.dependencies.advisory_enrichment."""
from __future__ import annotations

import json
import time
from pathlib import Path

import httpx
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _nvd_response(
    cve_id: str = "CVE-2021-23337",
    description: str = "Prototype pollution in lodash via defaultsDeep.",
    cvss_score: float = 7.2,
) -> dict:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "published": "2021-02-15T11:15:00.000",
                    "lastModified": "2021-03-01T00:00:00.000",
                    "descriptions": [
                        {"lang": "en", "value": description},
                        {"lang": "es", "value": "no debe usarse"},
                    ],
                    "references": [
                        {"url": "https://example.com/advisory/1"},
                        {"url": "https://github.com/lodash/lodash/issues/4874"},
                    ],
                    "weaknesses": [
                        {
                            "description": [
                                {"value": "CWE-1321"},
                                {"value": "NVD-CWE-noinfo"},
                            ]
                        }
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": cvss_score,
                                    "vectorString": "CVSS:3.1/AV:N",
                                }
                            }
                        ]
                    },
                    "configurations": [
                        {
                            "nodes": [
                                {
                                    "cpeMatch": [
                                        {
                                            "versionStartIncluding": "0.0.0",
                                            "versionEndExcluding": "4.17.21",
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                }
            }
        ]
    }


def _osv_response(
    advisory_id: str = "GHSA-35jh-r3h4-6jhm",
    summary: str = "Prototype pollution in lodash.",
    details: str = (
        "Versions of lodash prior to 4.17.21 are vulnerable to prototype pollution "
        "via _.defaultsDeep when handling attacker-controlled object keys."
    ),
) -> dict:
    return {
        "id": advisory_id,
        "summary": summary,
        "details": details,
        "published": "2021-02-15T11:15:00Z",
        "references": [
            {"url": "https://github.com/lodash/lodash/pull/5085"},
            {"url": "https://example.com/advisory/1"},  # dedup target
        ],
        "affected": [
            {
                "ranges": [
                    {
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ]
                    }
                ],
                "database_specific": {"cwe_ids": ["CWE-1321"]},
            }
        ],
    }


def _make_transport(handler):
    return httpx.MockTransport(handler)


def _client_with(handler) -> httpx.Client:
    return httpx.Client(transport=_make_transport(handler), timeout=5.0)


# ---------------------------------------------------------------------------
# fetch_advisory_details — core behavior
# ---------------------------------------------------------------------------


def test_fetch_ignores_non_advisory_ids(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request to {req.url}")

    result = fetch_advisory_details(
        ["", "not-an-id", "CVE-bad", "GHSA-foo"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    assert result == {}


def test_fetch_nvd_only_for_cve(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    def handler(req: httpx.Request) -> httpx.Response:
        if "services.nvd.nist.gov" in req.url.host:
            return httpx.Response(200, json=_nvd_response())
        if "api.osv.dev" in req.url.host:
            return httpx.Response(404)
        raise AssertionError(req.url)

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    detail = result["CVE-2021-23337"]
    assert detail.advisory_id == "CVE-2021-23337"
    assert "Prototype pollution" in detail.description
    assert "CWE-1321" in detail.cwes
    assert "NVD-CWE-noinfo" not in detail.cwes
    assert detail.vulnerable_version_range == ">= 0.0.0, < 4.17.21"
    assert "nvd" in detail.sources
    assert "https://example.com/advisory/1" in detail.references


def test_fetch_osv_only_for_ghsa(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    def handler(req: httpx.Request) -> httpx.Response:
        if "services.nvd.nist.gov" in req.url.host:
            raise AssertionError("NVD should not be queried for GHSA-only IDs")
        if "api.osv.dev" in req.url.host:
            return httpx.Response(200, json=_osv_response())
        raise AssertionError(req.url)

    result = fetch_advisory_details(
        ["GHSA-35jh-r3h4-6jhm"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    detail = result["GHSA-35jh-r3h4-6jhm"]
    assert "_.defaultsDeep" in detail.description
    assert "CWE-1321" in detail.cwes
    assert detail.vulnerable_version_range == "< 4.17.21"
    assert detail.sources == ("osv",)


def test_fetch_merges_nvd_and_osv(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    long_description = "x" * 800

    def handler(req: httpx.Request) -> httpx.Response:
        if "services.nvd.nist.gov" in req.url.host:
            return httpx.Response(200, json=_nvd_response(description="short"))
        if "api.osv.dev" in req.url.host:
            return httpx.Response(200, json=_osv_response(details=long_description))
        raise AssertionError(req.url)

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    detail = result["CVE-2021-23337"]
    # OSV's longer description wins
    assert detail.description == long_description
    # References from both, deduplicated
    assert "https://example.com/advisory/1" in detail.references
    assert "https://github.com/lodash/lodash/pull/5085" in detail.references
    assert (
        len([r for r in detail.references if r == "https://example.com/advisory/1"])
        == 1
    )
    # Both sources recorded
    assert set(detail.sources) == {"nvd", "osv"}


def test_fetch_returns_empty_when_both_sources_fail(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    def handler(req: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    assert result == {}


def test_fetch_tolerates_network_errors(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import fetch_advisory_details

    def handler(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    assert result == {}


# ---------------------------------------------------------------------------
# Cache behavior
# ---------------------------------------------------------------------------


def test_cache_hit_skips_network(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import (
        AdvisoryDetail,
        _AdvisoryCache,
        fetch_advisory_details,
    )

    cache = _AdvisoryCache(tmp_path, ttl_seconds=3600)
    cache.put(
        "CVE-2021-23337",
        AdvisoryDetail(
            advisory_id="CVE-2021-23337",
            description="cached",
            sources=("nvd",),
        ),
    )

    def handler(req: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected fetch on cache hit: {req.url}")

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        http_client=_client_with(handler),
    )
    assert result["CVE-2021-23337"].description == "cached"


def test_cache_ttl_expiry_refetches(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import (
        AdvisoryDetail,
        _AdvisoryCache,
        fetch_advisory_details,
    )

    cache = _AdvisoryCache(tmp_path, ttl_seconds=3600)
    cache.put(
        "CVE-2021-23337",
        AdvisoryDetail(advisory_id="CVE-2021-23337", description="stale"),
    )
    # Backdate the cache file
    import os as _os

    cache_path = cache._path("CVE-2021-23337")
    old = time.time() - 10_000
    _os.utime(cache_path, (old, old))

    def handler(req: httpx.Request) -> httpx.Response:
        if "services.nvd.nist.gov" in req.url.host:
            return httpx.Response(200, json=_nvd_response(description="fresh"))
        return httpx.Response(404)

    result = fetch_advisory_details(
        ["CVE-2021-23337"],
        cache_dir=tmp_path,
        cache_ttl_seconds=1,
        http_client=_client_with(handler),
    )
    assert result["CVE-2021-23337"].description == "fresh"


def test_cache_round_trip(tmp_path):
    from runner.scanners.dependencies.advisory_enrichment import (
        AdvisoryDetail,
        _AdvisoryCache,
    )

    detail = AdvisoryDetail(
        advisory_id="GHSA-x",
        summary="s",
        description="d",
        references=("https://a", "https://b"),
        cwes=("CWE-1",),
        vulnerable_version_range="< 1.0",
        published_at="2021-01-01",
        sources=("osv",),
    )
    cache = _AdvisoryCache(tmp_path, ttl_seconds=3600)
    cache.put("GHSA-x", detail)
    got = cache.get("GHSA-x")
    assert got == detail


# ---------------------------------------------------------------------------
# normalize.py integration
# ---------------------------------------------------------------------------


def test_attach_advisory_details_mutates_findings(tmp_path, monkeypatch):
    from runner.scanners.dependencies import advisory_enrichment, normalize

    def fake_fetch(ids, **kwargs):
        return {
            "CVE-2021-23337": advisory_enrichment.AdvisoryDetail(
                advisory_id="CVE-2021-23337",
                description="long advisory text from NVD",
                cwes=("CWE-1321",),
                sources=("nvd",),
            )
        }

    monkeypatch.setattr(
        advisory_enrichment, "fetch_advisory_details", fake_fetch
    )

    findings = [
        {
            "advisoryId": "GHSA-foo",
            "advisoryAliases": ["CVE-2021-23337"],
        },
        {
            "advisoryId": "CVE-2021-23337",
            "advisoryAliases": [],
        },
        {
            "advisoryId": "GHSA-unknown",
            "advisoryAliases": [],
        },
    ]

    normalize.attach_advisory_details(findings, cache_dir=tmp_path)

    # finding[0] resolves via alias
    assert findings[0]["advisoryDetail"]["description"] == "long advisory text from NVD"
    # finding[1] resolves via primary id
    assert findings[1]["advisoryDetail"]["description"] == "long advisory text from NVD"
    # finding[2] has no match → None
    assert findings[2]["advisoryDetail"] is None


def test_normalize_grype_output_respects_disable_env(
    tmp_path, monkeypatch
):
    from runner.scanners.dependencies import advisory_enrichment, normalize

    monkeypatch.setenv("AEGIS_DISABLE_EAGER_ENRICHMENT", "1")

    called = {"hit": False}

    def fake_fetch(ids, **kwargs):
        called["hit"] = True
        return {}

    monkeypatch.setattr(
        advisory_enrichment, "fetch_advisory_details", fake_fetch
    )

    repo_dir = tmp_path / "acme__widget"
    repo_dir.mkdir()
    (repo_dir / "head-sha.txt").write_text("abc\n")
    (repo_dir / "findings.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2021-23337",
                            "severity": "High",
                            "description": "short",
                        },
                        "artifact": {
                            "name": "lodash",
                            "version": "4.17.20",
                            "type": "npm",
                            "locations": [{"path": "/package.json"}],
                        },
                    }
                ]
            }
        )
    )

    total, errors = normalize.normalize_grype_output("acme", tmp_path, "run-1")
    assert total == 1
    assert errors == 0
    assert called["hit"] is False

    # Finding written but no advisoryDetail attached
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 1
    finding = json.loads(lines[0])
    assert "advisoryDetail" not in finding


def test_normalize_grype_output_attaches_when_enabled(tmp_path, monkeypatch):
    from runner.scanners.dependencies import advisory_enrichment, normalize

    monkeypatch.delenv("AEGIS_DISABLE_EAGER_ENRICHMENT", raising=False)

    def fake_fetch(ids, **kwargs):
        return {
            "CVE-2021-23337": advisory_enrichment.AdvisoryDetail(
                advisory_id="CVE-2021-23337",
                description="enriched prose",
                sources=("nvd",),
            )
        }

    monkeypatch.setattr(
        advisory_enrichment, "fetch_advisory_details", fake_fetch
    )

    repo_dir = tmp_path / "acme__widget"
    repo_dir.mkdir()
    (repo_dir / "head-sha.txt").write_text("abc\n")
    (repo_dir / "findings.json").write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "vulnerability": {
                            "id": "CVE-2021-23337",
                            "severity": "High",
                            "description": "short",
                        },
                        "artifact": {
                            "name": "lodash",
                            "version": "4.17.20",
                            "type": "npm",
                            "locations": [{"path": "/package.json"}],
                        },
                    }
                ]
            }
        )
    )

    total, _ = normalize.normalize_grype_output("acme", tmp_path, "run-1")
    assert total == 1

    finding = json.loads((tmp_path / "findings.jsonl").read_text().splitlines()[0])
    assert finding["advisoryDetail"]["description"] == "enriched prose"
    assert finding["advisoryDetail"]["sources"] == ["nvd"]
