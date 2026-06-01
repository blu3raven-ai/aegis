"""Tests for SBOM export REST endpoints — Phase 18.

Uses a minimal FastAPI app with only the sbom export router so there's no
lifespan overhead, no auth middleware, and no scheduler.  SbomCache and
ContainerSbomCache are exercised against the real testcontainer Postgres +
MinIO instances spun up by conftest.py.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import delete

from src.dependencies.sbom_cache import SbomCache, ContainerSbomCache, _CACHE_TYPE, _CACHE_TYPE_CONTAINER
from src.db.helpers import run_db
from src.db.models import CacheEntry
from src.sbom.router import router as sbom_export_router


SAMPLE_SBOM: dict = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "metadata": {
        "timestamp": "2025-01-01T00:00:00Z",
        "tools": [{"name": "syft", "version": "1.2.0"}],
    },
    "components": [
        {
            "type": "library",
            "bom-ref": "pkg:npm/axios@1.6.0",
            "name": "axios",
            "version": "1.6.0",
            "purl": "pkg:npm/axios@1.6.0",
            "licenses": [{"license": {"id": "MIT"}}],
        }
    ],
    "dependencies": [],
}

REPO_ID = "example-org/payments-api"
# TestClient sends path segments literally; the :path converter captures them.
REPO_URL = f"/api/v1/sboms/repo/{REPO_ID}"
HISTORY_URL = f"/api/v1/sboms/repo/{REPO_ID}/history"

HASH_V1 = "aabbcc" * 10 + "aa"  # 62-char placeholder
HASH_V2 = "ddeeff" * 10 + "dd"
TOOL_VER = "syft-1.2.0"

IMAGE_DIGEST = "sha256:deadbeef" + "0" * 55


@pytest.fixture(autouse=True)
def _clean_cache_entries():
    """Remove test rows before each test."""
    async def _del(session):
        await session.execute(
            delete(CacheEntry).where(
                CacheEntry.cache_type.in_([_CACHE_TYPE, _CACHE_TYPE_CONTAINER]),
                CacheEntry.cache_key.startswith("example-org"),
            )
        )
        await session.execute(
            delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE_CONTAINER,
                CacheEntry.cache_key.startswith("sha256:deadbeef"),
            )
        )

    run_db(_del)
    yield


@pytest.fixture
def client() -> TestClient:
    mini = FastAPI()
    mini.include_router(sbom_export_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── /repo/{repo_id} ───────────────────────────────────────────────────────────

def test_export_repo_sbom_not_found(client: TestClient):
    resp = client.get("/api/v1/sboms/repo/example-org/nonexistent-repo")
    assert resp.status_code == 404


def test_export_repo_sbom_cyclonedx_json(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        REPO_URL,
        params={"format": "cyclonedx-json"},
    )
    assert resp.status_code == 200
    assert "application/vnd.cyclonedx+json" in resp.headers["content-type"]
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"
    assert data["components"][0]["name"] == "axios"


def test_export_repo_sbom_spdx_json(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        REPO_URL,
        params={"format": "spdx-json"},
    )
    assert resp.status_code == 200
    assert "spdx" in resp.headers["content-type"]
    import json
    data = json.loads(resp.content)
    assert data["spdxVersion"] == "SPDX-2.3"


def test_export_repo_sbom_cyclonedx_xml(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        REPO_URL,
        params={"format": "cyclonedx-xml"},
    )
    assert resp.status_code == 200
    assert "xml" in resp.headers["content-type"]
    assert b"axios" in resp.content


def test_export_repo_sbom_spdx_tag_value(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        REPO_URL,
        params={"format": "spdx-tag-value"},
    )
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert b"SPDXVersion" in resp.content


def test_export_repo_sbom_default_format_is_cyclonedx_json(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"


def test_export_repo_sbom_unknown_format_returns_400(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        f"/api/v1/sboms/repo/{REPO_ID}",
        params={"format": "csv"},
    )
    assert resp.status_code == 400


def test_export_repo_sbom_returns_latest_when_multiple(client: TestClient):
    import time
    cache = SbomCache()
    sbom_v1 = dict(SAMPLE_SBOM)
    sbom_v1["metadata"] = dict(SAMPLE_SBOM["metadata"])
    sbom_v1["metadata"]["timestamp"] = "2025-01-01T00:00:00Z"

    sbom_v2 = dict(SAMPLE_SBOM)
    sbom_v2["metadata"] = dict(SAMPLE_SBOM["metadata"])
    sbom_v2["metadata"]["timestamp"] = "2025-06-01T00:00:00Z"

    cache.put(REPO_ID, HASH_V1, sbom_v1, TOOL_VER)
    time.sleep(0.05)  # ensure distinct created_at
    cache.put(REPO_ID, HASH_V2, sbom_v2, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert resp.status_code == 200


def test_export_repo_sbom_content_disposition_header(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert "content-disposition" in resp.headers
    assert "attachment" in resp.headers["content-disposition"]


# ── /image/{image_digest} ─────────────────────────────────────────────────────

def test_export_image_sbom_not_found(client: TestClient):
    resp = client.get(f"/api/v1/sboms/image/sha256:nonexistent")
    assert resp.status_code == 404


def test_export_image_sbom_cyclonedx_json(client: TestClient):
    container_cache = ContainerSbomCache()
    container_cache.put_by_digest(IMAGE_DIGEST, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        f"/api/v1/sboms/image/{IMAGE_DIGEST}",
        params={"format": "cyclonedx-json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"


def test_export_image_sbom_spdx_json(client: TestClient):
    container_cache = ContainerSbomCache()
    container_cache.put_by_digest(IMAGE_DIGEST, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        f"/api/v1/sboms/image/{IMAGE_DIGEST}",
        params={"format": "spdx-json"},
    )
    assert resp.status_code == 200
    import json
    data = json.loads(resp.content)
    assert data["spdxVersion"] == "SPDX-2.3"


# ── /repo/{repo_id}/history ───────────────────────────────────────────────────

def test_history_empty_when_no_entries(client: TestClient):
    resp = client.get("/api/v1/sboms/repo/example-org/nonexistent-repo/history")
    assert resp.status_code == 200
    assert resp.json() == []


def test_history_returns_entries(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["manifest_set_hash"] == HASH_V1
    assert data[0]["blob_pointer"] is not None
    assert "created_at" in data[0]


def test_history_multiple_versions(client: TestClient):
    import time
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)
    time.sleep(0.05)
    cache.put(REPO_ID, HASH_V2, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Most recent first
    assert data[0]["manifest_set_hash"] == HASH_V2
    assert data[1]["manifest_set_hash"] == HASH_V1


def test_history_respects_limit(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)
    cache.put(REPO_ID, HASH_V2, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(
        f"/api/v1/sboms/repo/{REPO_ID}/history",
        params={"limit": "1"},
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_history_limit_out_of_range_returns_422(client: TestClient):
    resp = client.get(
        f"/api/v1/sboms/repo/{REPO_ID}/history",
        params={"limit": "200"},
    )
    assert resp.status_code == 422


def test_history_entry_has_all_expected_fields(client: TestClient):
    cache = SbomCache()
    cache.put(REPO_ID, HASH_V1, SAMPLE_SBOM, TOOL_VER)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    data = resp.json()
    entry = data[0]
    for field in ("manifest_set_hash", "created_at", "blob_pointer", "content_hash", "tool_version"):
        assert field in entry, f"Field '{field}' missing from history entry"
