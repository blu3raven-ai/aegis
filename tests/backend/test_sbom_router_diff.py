"""Tests for the /api/v1/sboms/diff endpoint — Phase 37.

Uses a real testcontainer Postgres + MinIO so the full cache round-trip is
exercised.  The diff endpoint is purely read-only, so tests write SBOMs via
SbomCache.put / ContainerSbomCache.put_by_digest then assert on the diff.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.dependencies.sbom_cache import (
    SbomCache,
    ContainerSbomCache,
    _CACHE_TYPE,
    _CACHE_TYPE_CONTAINER,
)
from src.db.helpers import run_db
from src.db.models import CacheEntry
from src.sbom.router import router as sbom_router


# ── shared fixtures ───────────────────────────────────────────────────────────

REPO_ID = "example-org/sbom-diff-test"
HASH_A = "aaaa" * 15 + "aaaa"   # 64-char placeholder
HASH_B = "bbbb" * 15 + "bbbb"
TOOL_VER = "syft-1.2.0"

DIGEST_A = "sha256:aaaa" + "0" * 59
DIGEST_B = "sha256:bbbb" + "0" * 59

DIFF_URL = "/api/v1/sboms/diff"


def _make_sbom(*components: dict) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": list(components),
    }


def _pkg(name: str, version: str, purl: str | None = None) -> dict:
    c: dict = {"name": name, "version": version, "type": "library"}
    if purl is not None:
        c["purl"] = purl
    return c


LODASH = _pkg("lodash", "4.17.21", "pkg:npm/lodash@4.17.21")
REACT = _pkg("react", "18.2.0", "pkg:npm/react@18.2.0")
AXIOS_OLD = _pkg("axios", "1.3.0", None)
AXIOS_NEW = _pkg("axios", "1.6.0", None)


@pytest.fixture(autouse=True)
def _clean():
    """Remove test rows before each test to ensure isolation."""
    async def _del(session):
        await session.execute(
            delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.startswith(REPO_ID),
            )
        )
        await session.execute(
            delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE_CONTAINER,
                CacheEntry.cache_key.in_([DIGEST_A, DIGEST_B]),
            )
        )

    run_db(_del)
    yield


@pytest.fixture
def client() -> TestClient:
    mini = FastAPI()
    mini.include_router(sbom_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── missing params → 400 ──────────────────────────────────────────────────────

def test_diff_missing_all_params_returns_400(client):
    resp = client.get(DIFF_URL, params={"from_hash": "x", "to_hash": "y"})
    assert resp.status_code == 400


def test_diff_missing_from_hash_returns_400(client):
    resp = client.get(DIFF_URL, params={"repo_id": REPO_ID, "to_hash": HASH_B})
    assert resp.status_code == 400


def test_diff_missing_to_hash_returns_400(client):
    resp = client.get(DIFF_URL, params={"repo_id": REPO_ID, "from_hash": HASH_A})
    assert resp.status_code == 400


# ── cache miss → 404 ─────────────────────────────────────────────────────────

def test_diff_from_hash_not_in_cache_returns_404(client):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_B, _make_sbom(LODASH), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 404


def test_diff_to_hash_not_in_cache_returns_404(client):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, _make_sbom(LODASH), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 404


# ── repo-based diff ───────────────────────────────────────────────────────────

def test_diff_identical_sboms_returns_all_unchanged(client):
    sbom = _make_sbom(LODASH, REACT)
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, sbom, TOOL_VER)
    cache.put(REPO_ID, HASH_B, sbom, TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["added"] == []
    assert data["removed"] == []
    assert data["version_changed"] == []
    assert data["unchanged_count"] == 2


def test_diff_added_component(client):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, _make_sbom(LODASH), TOOL_VER)
    cache.put(REPO_ID, HASH_B, _make_sbom(LODASH, REACT), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["added"]) == 1
    assert data["added"][0]["name"] == "react"
    assert data["removed"] == []
    assert data["unchanged_count"] == 1


def test_diff_removed_component(client):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, _make_sbom(LODASH, REACT), TOOL_VER)
    cache.put(REPO_ID, HASH_B, _make_sbom(LODASH), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["added"] == []
    assert len(data["removed"]) == 1
    assert data["removed"][0]["name"] == "react"
    assert data["unchanged_count"] == 1


def test_diff_version_changed(client):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, _make_sbom(AXIOS_OLD), TOOL_VER)
    cache.put(REPO_ID, HASH_B, _make_sbom(AXIOS_NEW), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["added"] == []
    assert data["removed"] == []
    assert len(data["version_changed"]) == 1
    change = data["version_changed"][0]
    assert change["name"] == "axios"
    assert change["from_version"] == "1.3.0"
    assert change["to_version"] == "1.6.0"


def test_diff_mixed_changes(client):
    """Add, remove, version bump, and unchanged all in one request."""
    old_axios = _pkg("axios", "1.3.0")
    new_axios = _pkg("axios", "1.6.0")
    jquery = _pkg("jquery", "3.6.0")

    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, _make_sbom(old_axios, jquery, LODASH), TOOL_VER)
    cache.put(REPO_ID, HASH_B, _make_sbom(new_axios, LODASH, REACT), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["added"]) == 1
    assert data["added"][0]["name"] == "react"
    assert len(data["removed"]) == 1
    assert data["removed"][0]["name"] == "jquery"
    assert len(data["version_changed"]) == 1
    assert data["version_changed"][0]["from_version"] == "1.3.0"
    assert data["unchanged_count"] == 1


# ── container-digest-based diff ───────────────────────────────────────────────

def test_diff_by_image_digest(client):
    ccache = ContainerSbomCache()
    ccache.put_by_digest(DIGEST_A, _make_sbom(LODASH), TOOL_VER)
    ccache.put_by_digest(DIGEST_B, _make_sbom(LODASH, REACT), TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={
            "from_hash": "ignored",
            "to_hash": "ignored",
            "image_digest_from": DIGEST_A,
            "image_digest_to": DIGEST_B,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["added"]) == 1
    assert data["added"][0]["name"] == "react"
    assert data["unchanged_count"] == 1


def test_diff_image_digest_one_missing_returns_404(client):
    ccache = ContainerSbomCache()
    ccache.put_by_digest(DIGEST_A, _make_sbom(LODASH), TOOL_VER)
    # DIGEST_B intentionally not stored

    resp = client.get(
        DIFF_URL,
        params={
            "from_hash": "ignored",
            "to_hash": "ignored",
            "image_digest_from": DIGEST_A,
            "image_digest_to": DIGEST_B,
        },
    )
    assert resp.status_code == 404


# ── response shape ────────────────────────────────────────────────────────────

def test_diff_response_has_expected_keys(client):
    sbom = _make_sbom(LODASH)
    cache = SbomCache()
    cache.put(REPO_ID, HASH_A, sbom, TOOL_VER)
    cache.put(REPO_ID, HASH_B, sbom, TOOL_VER)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_hash": HASH_A, "to_hash": HASH_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"added", "removed", "version_changed", "unchanged_count"}
    assert isinstance(data["added"], list)
    assert isinstance(data["removed"], list)
    assert isinstance(data["version_changed"], list)
    assert isinstance(data["unchanged_count"], int)
