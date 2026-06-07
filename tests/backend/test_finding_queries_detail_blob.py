"""Integration tests for upsert_finding detail blob offload.

Verifies that the write path correctly splits detail into lean JSONB and fat
MinIO blob, with proper key lifecycle (create, overwrite, delete).

Requires testcontainers Postgres + MinIO (both started by conftest.py).

The compliance auto-mapper is patched out so that INSERT operations commit
cleanly even in a test DB that lacks the compliance_control_mappings table.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch, AsyncMock
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Finding
from src.shared.finding_detail_blob import LEAN_KEYS, build_blob_key
from src.shared.finding_queries import upsert_finding
from src.shared.object_store import download_json


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOOL = "code_scanning"
_ORG = "blob-upsert-test-org"

# Suppress the compliance auto-mapper for all tests in this module — the test
# DB does not have the compliance_control_mappings table, so the mapper would
# abort the INSERT transaction and prevent detail_blob_key from committing.
@pytest.fixture(autouse=True)
def _no_compliance_mapper():
    async def _noop(*args, **kwargs):
        pass

    with patch("src.compliance.auto_mapper.apply_finding_mappings", side_effect=_noop):
        yield


def _make_detail(*, fat: bool) -> dict:
    """Build a detail dict with lean-only or lean+fat keys."""
    lean_part = {
        "ruleId": "java/sqli",
        "startLine": 10,
        "endLine": 12,
        "message": "Unsafe query",
        "category": "security",
        "cwe": ["CWE-89"],
        "owasp": [],
        "confidence": "high",
        "language": "java",
        "fileClass": "source",
        "ruleIds": ["java/sqli"],
    }
    if fat:
        lean_part["snippet"] = "String q = input;"
        lean_part["dataflowTrace"] = {"nodes": [{"file": "App.java", "line": 5}]}
        lean_part["fixSuggestion"] = "Use PreparedStatement"
    return lean_part


def _clean(org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == org)
        )
    run_db(_del)


def _fetch(org: str, identity_key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.org == org,
                Finding.identity_key == identity_key,
            )
        )
        return result.scalars().first()
    return run_db(_q)


def _upsert(org: str, identity_key: str, detail: dict) -> Finding:
    async def _q(session):
        return await upsert_finding(
            session,
            tool=_TOOL,
            org=org,
            repo=f"{org}/api",
            identity_key=identity_key,
            state="open",
            severity="high",
            detail=detail,
        )
    return run_db(_q)


# ---------------------------------------------------------------------------
# INSERT tests
# ---------------------------------------------------------------------------

def test_insert_with_fat_detail_splits_and_uploads_blob(s3_endpoint):
    """Insert with rich (fat) detail: lean keys in JSONB, fat keys in MinIO."""
    org = f"{_ORG}-insert-fat"
    key = "test-sqli-fat-insert"
    _clean(org)

    detail = _make_detail(fat=True)
    fat_keys = {"snippet", "dataflowTrace", "fixSuggestion"}
    lean_keys = LEAN_KEYS[_TOOL]

    finding = _upsert(org, key, detail)

    assert finding.id is not None
    # Lean column must only contain lean keys
    for k in fat_keys:
        assert k not in finding.detail, f"fat key {k!r} leaked into lean JSONB"
    for k in lean_keys:
        if k in detail:
            assert k in finding.detail, f"lean key {k!r} missing from JSONB"

    # Blob key must be set and point to correct path
    expected_key = build_blob_key(finding.id)
    assert finding.detail_blob_key == expected_key

    # Downloading the blob must yield the fat subset
    blob = download_json(expected_key)
    assert blob is not None
    for k in fat_keys:
        assert k in blob, f"fat key {k!r} missing from MinIO blob"
    for k in lean_keys:
        assert k not in blob, f"lean key {k!r} should not be in blob"


def test_insert_with_lean_only_detail_no_blob(s3_endpoint):
    """Insert with lean-only detail: detail_blob_key stays None, no MinIO write."""
    org = f"{_ORG}-insert-lean"
    key = "test-sqli-lean-insert"
    _clean(org)

    detail = _make_detail(fat=False)
    finding = _upsert(org, key, detail)

    assert finding.detail_blob_key is None
    # Nothing uploaded — listing the expected key should return None
    blob = download_json(build_blob_key(finding.id))
    assert blob is None


# ---------------------------------------------------------------------------
# UPDATE tests
# ---------------------------------------------------------------------------

def test_update_creates_blob_when_fat_keys_added(s3_endpoint):
    """Update an existing lean-only finding with fat detail: blob created, key set."""
    org = f"{_ORG}-update-create"
    key = "test-sqli-update-create"
    _clean(org)

    # First insert lean-only
    f1 = _upsert(org, key, _make_detail(fat=False))
    assert f1.detail_blob_key is None

    # Now update with fat detail
    f2 = _upsert(org, key, _make_detail(fat=True))

    assert f2.detail_blob_key == build_blob_key(f2.id)
    blob = download_json(f2.detail_blob_key)
    assert blob is not None
    assert "snippet" in blob


def test_update_clears_blob_when_fat_keys_removed(s3_endpoint):
    """Update an existing fat finding with lean-only detail: blob deleted, key cleared."""
    org = f"{_ORG}-update-clear"
    key = "test-sqli-update-clear"
    _clean(org)

    # First insert with fat detail to create the blob
    f1 = _upsert(org, key, _make_detail(fat=True))
    prior_blob_key = f1.detail_blob_key
    assert prior_blob_key is not None

    # Update with lean-only detail
    f2 = _upsert(org, key, _make_detail(fat=False))

    assert f2.detail_blob_key is None
    # The old blob must have been deleted
    blob = download_json(prior_blob_key)
    assert blob is None


def test_update_overwrites_blob_when_fat_keys_present(s3_endpoint):
    """Update a fat finding with updated fat detail: blob overwritten, key unchanged."""
    org = f"{_ORG}-update-overwrite"
    key = "test-sqli-update-overwrite"
    _clean(org)

    detail_v1 = {**_make_detail(fat=True), "snippet": "version one"}
    f1 = _upsert(org, key, detail_v1)
    key_v1 = f1.detail_blob_key
    assert key_v1 is not None

    detail_v2 = {**_make_detail(fat=True), "snippet": "version two"}
    f2 = _upsert(org, key, detail_v2)

    # Stable key — same finding id
    assert f2.detail_blob_key == key_v1

    blob = download_json(f2.detail_blob_key)
    assert blob is not None
    assert blob["snippet"] == "version two"
