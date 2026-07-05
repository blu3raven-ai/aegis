"""Unit tests for the OSV store layer.

Two methods under test:
  - upsert_advisories(advisories): writes header rows to Postgres + blob to MinIO
  - get_advisory_detail(advisory_id): reads header from Postgres + body from MinIO

Storage shape:
  Postgres osv_advisories     — searchable header
  Postgres osv_vulnerable_ranges — query index for matching
  MinIO osv/{ecosystem}/{advisory_id}.json — full body
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from src.osv.store import OsvStore


def _adv(adv_id: str = "GHSA-aaaa", ecosystem: str = "npm", modified: str = "2026-06-15T00:00:00Z") -> dict:
    return {
        "id": adv_id,
        "summary": f"{adv_id} summary",
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "published": "2026-06-01T00:00:00Z",
        "modified": modified,
        "affected": [
            {
                "package": {"name": "osvstorepkg", "ecosystem": ecosystem},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.asyncio
async def test_upsert_advisories_writes_postgres_and_minio(monkeypatch):
    store = OsvStore()
    advisories = [_adv("GHSA-aaaa")]

    minio_writes: list[tuple[str, bytes]] = []
    monkeypatch.setattr(
        "src.osv.store._upload_blob",
        lambda key, data, bucket=None: minio_writes.append((key, data)),
    )

    written = await store.upsert_advisories(advisories, ecosystem="npm")

    assert written == 1
    assert minio_writes == [
        ("osv/npm/GHSA-aaaa.json", pytest.approx(minio_writes[0][1])),
    ]
    assert minio_writes[0][0] == "osv/npm/GHSA-aaaa.json"


@pytest.mark.asyncio
async def test_upsert_advisories_replaces_existing_ranges(monkeypatch):
    """When an advisory is re-imported, its vulnerable_ranges rows must be
    replaced wholesale — never accumulated. Tests with a fixture advisory
    written twice with different ranges; only the second set should remain."""
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)

    first = _adv("GHSA-aaaa")
    # Same advisory_id, different package
    second = dict(first)
    second["affected"] = [
        {
            "package": {"name": "different-pkg", "ecosystem": "npm"},
            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}],
        }
    ]

    await store.upsert_advisories([first], ecosystem="npm")
    await store.upsert_advisories([second], ecosystem="npm")

    ranges = await store.list_ranges_for_advisory("GHSA-aaaa")
    package_names = {r.package_name for r in ranges}
    assert package_names == {"different-pkg"}


@pytest.mark.asyncio
async def test_get_advisory_detail_returns_header_plus_blob(monkeypatch):
    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)

    fake_body = b'{"id": "GHSA-aaaa", "details": "full markdown body here"}'
    monkeypatch.setattr("src.osv.store._download_blob", lambda key, bucket=None: fake_body)

    await store.upsert_advisories([_adv("GHSA-aaaa")], ecosystem="npm")

    detail = await store.get_advisory_detail("GHSA-aaaa")
    assert detail is not None
    assert detail["advisory_id"] == "GHSA-aaaa"
    assert detail["body"]["details"] == "full markdown body here"


@pytest.mark.asyncio
async def test_get_advisory_detail_returns_none_when_missing():
    store = OsvStore()
    detail = await store.get_advisory_detail("GHSA-does-not-exist")
    assert detail is None


@pytest.mark.asyncio
async def test_upsert_advisories_stores_long_distro_ecosystem(monkeypatch):
    """Linux-distro OSV ecosystems are unbounded upstream and must persist without
    truncation. SUSE module names are the worst case seen in the wild — this one is
    59 chars and used to abort the nightly refresh with a right-truncation error.
    Guards against regressing `ecosystem` back to any bounded VARCHAR type."""
    long_ecosystem = "SUSE:Linux Enterprise Module for Server Applications 15 SP3"
    assert len(long_ecosystem) > 32

    store = OsvStore()
    monkeypatch.setattr("src.osv.store._upload_blob", lambda *a, **k: None)

    written = await store.upsert_advisories(
        [_adv("SUSE-SU-0001-1", ecosystem=long_ecosystem)], ecosystem=long_ecosystem
    )

    assert written == 1
    ranges = await store.list_ranges_for_advisory("SUSE-SU-0001-1")
    assert ranges
    assert all(r.ecosystem == long_ecosystem for r in ranges)
