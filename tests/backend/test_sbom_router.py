"""Tests for SBOM export REST endpoints — Phase 18.

Uses a minimal FastAPI app with only the sbom export router.  SBOMs are seeded
directly into MinIO at the runner-owned paths and served back through the
rewired router.  Exercises a real testcontainer Postgres + MinIO round-trip.
"""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.shared.object_store import upload_bytes, get_s3_client
from src.containers.sbom_store import upsert_sbom as container_upsert_sbom
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

ORG = "example-org"
REPO = "payments-api"
REPO_ID = f"{ORG}/{REPO}"
REPO_URL = f"/api/v1/sboms/repo/{REPO_ID}"
HISTORY_URL = f"/api/v1/sboms/repo/{REPO_ID}/history"

RUN_ID_V1 = "auto-1748700000000"
RUN_ID_V2 = "auto-1748800000000"  # higher → newer

IMAGE_DIGEST = "sha256:deadbeef" + "0" * 55
IMAGE_REF = "registry.example.com/myapp:latest"


def _dep_key(org: str, run_id: str, repo: str) -> str:
    """Runner-owned MinIO key for a dependency SBOM."""
    return f"dependencies/{org}/{run_id}/{repo}/sbom.cdx.json"


def _upload_dep_sbom(org: str, run_id: str, repo: str, sbom: dict) -> str:
    """Upload a dependency SBOM at the runner-owned path; returns the key."""
    key = _dep_key(org, run_id, repo)
    upload_bytes(key, json.dumps(sbom).encode(), content_type="application/json")
    return key


@pytest.fixture(autouse=True)
def _clean_minio():
    """Delete test objects and Sbom rows before each test for isolation."""
    import os
    from src.db.helpers import run_db
    from src.db.models import Sbom
    from sqlalchemy import delete

    # Remove Sbom rows for test image digest so container lookups start clean
    async def _del_sboms(session):
        await session.execute(
            delete(Sbom).where(Sbom.commit_sha == IMAGE_DIGEST)
        )

    run_db(_del_sboms)

    s3 = get_s3_client()
    bucket = os.environ.get("S3_BUCKET", "scans")
    for run_id in (RUN_ID_V1, RUN_ID_V2):
        try:
            s3.delete_object(Bucket=bucket, Key=_dep_key(ORG, run_id, REPO))
        except Exception:
            pass
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
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(REPO_URL, params={"format": "cyclonedx-json"})
    assert resp.status_code == 200
    assert "application/vnd.cyclonedx+json" in resp.headers["content-type"]
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"
    assert data["components"][0]["name"] == "axios"


def test_export_repo_sbom_spdx_json(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(REPO_URL, params={"format": "spdx-json"})
    assert resp.status_code == 200
    assert "spdx" in resp.headers["content-type"]
    data = json.loads(resp.content)
    assert data["spdxVersion"] == "SPDX-2.3"


def test_export_repo_sbom_cyclonedx_xml(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(REPO_URL, params={"format": "cyclonedx-xml"})
    assert resp.status_code == 200
    assert "xml" in resp.headers["content-type"]
    assert b"axios" in resp.content


def test_export_repo_sbom_spdx_tag_value(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(REPO_URL, params={"format": "spdx-tag-value"})
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    assert b"SPDXVersion" in resp.content


def test_export_repo_sbom_default_format_is_cyclonedx_json(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"


def test_export_repo_sbom_unknown_format_returns_400(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}", params={"format": "csv"})
    assert resp.status_code == 400


def test_export_repo_sbom_returns_latest_when_multiple(client: TestClient):
    sbom_v1 = dict(SAMPLE_SBOM)
    sbom_v1["metadata"] = dict(SAMPLE_SBOM["metadata"])
    sbom_v1["metadata"]["timestamp"] = "2025-01-01T00:00:00Z"

    sbom_v2 = dict(SAMPLE_SBOM)
    sbom_v2["metadata"] = dict(SAMPLE_SBOM["metadata"])
    sbom_v2["metadata"]["timestamp"] = "2025-06-01T00:00:00Z"

    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, sbom_v1)
    _upload_dep_sbom(ORG, RUN_ID_V2, REPO, sbom_v2)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert resp.status_code == 200
    # RUN_ID_V2 sorts higher → should return the v2 SBOM
    data = resp.json()
    assert data["metadata"]["timestamp"] == "2025-06-01T00:00:00Z"


def test_export_repo_sbom_content_disposition_header(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}")
    assert "content-disposition" in resp.headers
    assert "attachment" in resp.headers["content-disposition"]


# ── /image/{image_digest} ─────────────────────────────────────────────────────

def test_export_image_sbom_not_found(client: TestClient):
    resp = client.get("/api/v1/sboms/image/sha256:nonexistent")
    assert resp.status_code == 404
    # No DB row for this digest
    assert "No SBOM found" in resp.json()["detail"]


def test_export_image_sbom_blob_missing(client: TestClient):
    """Test when DB row exists but MinIO blob is missing."""
    from src.db.helpers import run_db
    from src.db.models import Sbom

    # Create a DB row pointing to a non-existent MinIO key
    missing_s3_key = "container_scanning/example-org/auto-1748700000000/app/sbom.cdx.json"

    async def _insert_sbom(session):
        session.add(Sbom(
            org="example-org",
            repo=IMAGE_REF,
            commit_sha=IMAGE_DIGEST,
            s3_key=missing_s3_key,
            run_id=RUN_ID_V1,
        ))

    run_db(_insert_sbom)

    resp = client.get(f"/api/v1/sboms/image/{IMAGE_DIGEST}")
    assert resp.status_code == 404
    # DB row exists but blob is missing
    assert "SBOM blob not found" in resp.json()["detail"]


def test_export_image_sbom_cyclonedx_json(client: TestClient):
    container_upsert_sbom(ORG, IMAGE_REF, IMAGE_DIGEST, SAMPLE_SBOM, RUN_ID_V1)

    resp = client.get(
        f"/api/v1/sboms/image/{IMAGE_DIGEST}",
        params={"format": "cyclonedx-json"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["bomFormat"] == "CycloneDX"


def test_export_image_sbom_spdx_json(client: TestClient):
    container_upsert_sbom(ORG, IMAGE_REF, IMAGE_DIGEST, SAMPLE_SBOM, RUN_ID_V1)

    resp = client.get(
        f"/api/v1/sboms/image/{IMAGE_DIGEST}",
        params={"format": "spdx-json"},
    )
    assert resp.status_code == 200
    data = json.loads(resp.content)
    assert data["spdxVersion"] == "SPDX-2.3"


# ── /repo/{repo_id}/history ───────────────────────────────────────────────────

def test_history_empty_when_no_entries(client: TestClient):
    resp = client.get("/api/v1/sboms/repo/example-org/nonexistent-repo/history")
    assert resp.status_code == 200
    assert resp.json() == []


def test_history_returns_entries(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["run_id"] == RUN_ID_V1
    assert data[0]["key"] == _dep_key(ORG, RUN_ID_V1, REPO)
    assert "created_at" in data[0]
    # Regression guard: old field names must not appear
    assert "manifest_set_hash" not in data[0]
    assert "blob_pointer" not in data[0]
    assert "content_hash" not in data[0]
    assert "tool_version" not in data[0]


def test_history_multiple_versions(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)
    _upload_dep_sbom(ORG, RUN_ID_V2, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 2
    # Most recent run_id first (lex-sort descending)
    assert data[0]["run_id"] == RUN_ID_V2
    assert data[1]["run_id"] == RUN_ID_V1


def test_history_respects_limit(client: TestClient):
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)
    _upload_dep_sbom(ORG, RUN_ID_V2, REPO, SAMPLE_SBOM)

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
    _upload_dep_sbom(ORG, RUN_ID_V1, REPO, SAMPLE_SBOM)

    resp = client.get(f"/api/v1/sboms/repo/{REPO_ID}/history")
    data = resp.json()
    entry = data[0]
    for field in ("run_id", "created_at", "key"):
        assert field in entry, f"Field '{field}' missing from history entry"
