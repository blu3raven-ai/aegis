"""Tests for the /api/v1/sboms/diff endpoint — Phase 37.

Uses real testcontainer Postgres + MinIO.  SBOMs are seeded directly at
runner-owned MinIO paths (for repo diffs) or via the containers/sbom_store
upsert (for image-digest diffs), then the diff endpoint is exercised end-to-end.
"""
from __future__ import annotations

import json
import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.shared.object_store import upload_bytes, get_s3_client
from src.containers.sbom_store import upsert_sbom as container_upsert_sbom
from src.sbom.router import router as sbom_router


# ── shared fixtures ───────────────────────────────────────────────────────────

ORG = "example-org"
REPO = "sbom-diff-test"
REPO_ID = f"{ORG}/{REPO}"

RUN_ID_A = "auto-1748700000000"
RUN_ID_B = "auto-1748800000000"

DIGEST_A = "sha256:aaaa" + "0" * 59
DIGEST_B = "sha256:bbbb" + "0" * 59
IMAGE_REF_A = "registry.example.com/app:1.0"
IMAGE_REF_B = "registry.example.com/app:2.0"

DIFF_URL = "/api/v1/sboms/diff"


def _dep_key(org: str, run_id: str, repo: str) -> str:
    return f"dependencies/{org}/{run_id}/{repo}/sbom.cdx.json"


def _upload_dep_sbom(org: str, run_id: str, repo: str, sbom: dict) -> None:
    key = _dep_key(org, run_id, repo)
    upload_bytes(key, json.dumps(sbom).encode(), content_type="application/json")


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
    """Delete test MinIO objects and Sbom rows before each test."""
    from src.db.helpers import run_db
    from src.db.models import Sbom
    from sqlalchemy import delete

    # Remove Sbom rows for test image refs so digest lookups start clean
    async def _del_sboms(session):
        await session.execute(
            delete(Sbom).where(
                Sbom.commit_sha.in_([DIGEST_A, DIGEST_B])
            )
        )

    run_db(_del_sboms)

    s3 = get_s3_client()
    bucket = os.environ.get("S3_BUCKET", "scans")
    for run_id in (RUN_ID_A, RUN_ID_B):
        try:
            s3.delete_object(Bucket=bucket, Key=_dep_key(ORG, run_id, REPO))
        except Exception:
            pass
    yield


@pytest.fixture
def client() -> TestClient:
    mini = FastAPI()
    mini.include_router(sbom_router)
    return TestClient(mini, raise_server_exceptions=True)


# ── missing params → 400 ──────────────────────────────────────────────────────

def test_diff_missing_all_params_returns_400(client):
    resp = client.get(DIFF_URL, params={"from_run_id": "x", "to_run_id": "y"})
    assert resp.status_code == 400


def test_diff_missing_from_run_id_returns_400(client):
    resp = client.get(DIFF_URL, params={"repo_id": REPO_ID, "to_run_id": RUN_ID_B})
    assert resp.status_code == 400


def test_diff_missing_to_run_id_returns_400(client):
    resp = client.get(DIFF_URL, params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A})
    assert resp.status_code == 400


# ── SBOM not in MinIO → 404 ───────────────────────────────────────────────────

def test_diff_from_run_id_not_in_minio_returns_404(client):
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, _make_sbom(LODASH))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 404


def test_diff_to_run_id_not_in_minio_returns_404(client):
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, _make_sbom(LODASH))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 404


# ── repo-based diff ───────────────────────────────────────────────────────────

def test_diff_identical_sboms_returns_all_unchanged(client):
    sbom = _make_sbom(LODASH, REACT)
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, sbom)
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, sbom)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["added"] == []
    assert data["removed"] == []
    assert data["version_changed"] == []
    assert data["unchanged_count"] == 2


def test_diff_added_component(client):
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, _make_sbom(LODASH))
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, _make_sbom(LODASH, REACT))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["added"]) == 1
    assert data["added"][0]["name"] == "react"
    assert data["removed"] == []
    assert data["unchanged_count"] == 1


def test_diff_removed_component(client):
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, _make_sbom(LODASH, REACT))
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, _make_sbom(LODASH))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["added"] == []
    assert len(data["removed"]) == 1
    assert data["removed"][0]["name"] == "react"
    assert data["unchanged_count"] == 1


def test_diff_version_changed(client):
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, _make_sbom(AXIOS_OLD))
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, _make_sbom(AXIOS_NEW))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
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

    _upload_dep_sbom(ORG, RUN_ID_A, REPO, _make_sbom(old_axios, jquery, LODASH))
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, _make_sbom(new_axios, LODASH, REACT))

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
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
    container_upsert_sbom(ORG, IMAGE_REF_A, DIGEST_A, _make_sbom(LODASH), RUN_ID_A)
    container_upsert_sbom(ORG, IMAGE_REF_B, DIGEST_B, _make_sbom(LODASH, REACT), RUN_ID_B)

    resp = client.get(
        DIFF_URL,
        params={
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
    container_upsert_sbom(ORG, IMAGE_REF_A, DIGEST_A, _make_sbom(LODASH), RUN_ID_A)
    # DIGEST_B intentionally not stored

    resp = client.get(
        DIFF_URL,
        params={
            "image_digest_from": DIGEST_A,
            "image_digest_to": DIGEST_B,
        },
    )
    assert resp.status_code == 404


# ── response shape ────────────────────────────────────────────────────────────

def test_diff_response_has_expected_keys(client):
    sbom = _make_sbom(LODASH)
    _upload_dep_sbom(ORG, RUN_ID_A, REPO, sbom)
    _upload_dep_sbom(ORG, RUN_ID_B, REPO, sbom)

    resp = client.get(
        DIFF_URL,
        params={"repo_id": REPO_ID, "from_run_id": RUN_ID_A, "to_run_id": RUN_ID_B},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert set(data.keys()) == {"added", "removed", "version_changed", "unchanged_count"}
    assert isinstance(data["added"], list)
    assert isinstance(data["removed"], list)
    assert isinstance(data["version_changed"], list)
    assert isinstance(data["unchanged_count"], int)
