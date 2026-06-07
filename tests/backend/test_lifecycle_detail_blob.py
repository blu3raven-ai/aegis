"""Integration tests for _apply_detail in the lifecycle write path.

Exercises the dismissed-prev and regular-rescan branches via apply_lifecycle,
asserting that:
  - lean JSONB is correctly split
  - fat content lands in MinIO
  - blob key is set / cleared on the finding row

Requires testcontainers Postgres + MinIO (both started by conftest.py).
"""
from __future__ import annotations

import pytest
from unittest.mock import patch
from sqlalchemy import delete as sa_delete, select

from src.db.helpers import run_db
from src.db.models import Decision, Finding
from src.shared.finding_detail_blob import build_blob_key
from src.shared.finding_queries import upsert_decision
from src.shared.lifecycle import apply_lifecycle, ScanContext, LifecycleHooks
from src.shared.object_store import download_json


# ---------------------------------------------------------------------------
# Hooks
# ---------------------------------------------------------------------------

class _CodeScanHooks(LifecycleHooks):
    tool = "code_scanning"

    def compute_identity_key(self, raw: dict) -> str:
        return raw.get("key", "")

    def initial_state(self, raw: dict) -> str:
        return raw.get("state", "open")

    def extract_repo(self, raw: dict) -> str | None:
        return raw.get("repo", "acme-org/api")

    def extract_severity(self, raw: dict) -> str | None:
        return raw.get("severity", "high")

    def extract_detail(self, raw: dict) -> dict:
        return raw.get("detail", {})

    def should_mark_fixed(self, identity_key: str, prev_detail: dict, **kwargs) -> bool:
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TOOL = "code_scanning"
_HOOKS = _CodeScanHooks()

_FAT_DETAIL = {
    "ruleId": "java/sqli",
    "ruleName": "SQL Injection",
    "filePath": "src/App.java",
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
    # fat keys
    "snippet": "String q = input;",
    "dataflowTrace": {"nodes": [{"file": "App.java", "line": 5}]},
}

_LEAN_DETAIL = {
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


def _clean(org: str) -> None:
    async def _del(session):
        await session.execute(
            sa_delete(Finding).where(Finding.tool == _TOOL, Finding.org == org)
        )
        await session.execute(
            sa_delete(Decision).where(Decision.tool == _TOOL, Decision.org == org)
        )
    run_db(_del)


def _fetch_finding(org: str, key: str) -> Finding | None:
    async def _q(session):
        result = await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.org == org,
                Finding.identity_key == key,
            )
        )
        return result.scalars().first()
    return run_db(_q)


def _seed_finding(org: str, key: str, state: str, detail: dict) -> Finding:
    """Insert a Finding directly, bypassing the write-path splitter, to simulate
    an existing row in the DB from before the blob offload migration."""
    async def _q(session):
        f = Finding(
            tool=_TOOL,
            org=org,
            repo="acme-org/api",
            identity_key=key,
            state=state,
            severity="high",
            detail=detail,
        )
        session.add(f)
        await session.flush()
        return f
    return run_db(_q)


def _dismiss(org: str, key: str) -> None:
    async def _q(session):
        await upsert_decision(
            session, tool=_TOOL, org=org, identity_key=key,
            status="dismissed", reason="Risk is tolerable", decided_by="tester",
        )
    run_db(_q)


def _run_scan(org: str, raw_findings: list[dict]) -> list[dict]:
    ctx = ScanContext(tool=_TOOL, org=org, run_id="run-test")
    return apply_lifecycle(_HOOKS, ctx, raw_findings)


# ---------------------------------------------------------------------------
# Branch: regular rescan (existing open finding, no special state)
# ---------------------------------------------------------------------------

def test_regular_rescan_fat_detail_creates_blob(s3_endpoint):
    """Regular rescan with fat detail writes blob and sets blob key."""
    org = "lifecycle-blob-rescan-1"
    key = "sqli-fat"
    _clean(org)

    # Seed an open finding with lean-only detail (pre-migration style)
    _seed_finding(org, key, "open", _LEAN_DETAIL)

    _run_scan(org, [{"key": key, "detail": _FAT_DETAIL}])

    finding = _fetch_finding(org, key)
    assert finding is not None
    assert finding.detail_blob_key == build_blob_key(finding.id)
    assert "snippet" not in finding.detail
    assert "dataflowTrace" not in finding.detail
    assert finding.detail.get("ruleId") == "java/sqli"

    blob = download_json(finding.detail_blob_key)
    assert blob is not None
    assert blob.get("snippet") == "String q = input;"


def test_regular_rescan_lean_only_clears_blob(s3_endpoint):
    """Regular rescan with lean-only detail deletes any prior blob."""
    from src.shared.object_store import upload_bytes
    import json

    org = "lifecycle-blob-rescan-2"
    key = "sqli-lean-clear"
    _clean(org)

    # Seed finding and manually plant a blob to simulate prior state
    f = _seed_finding(org, key, "open", _LEAN_DETAIL)
    prior_blob_key = build_blob_key(f.id)
    upload_bytes(prior_blob_key, json.dumps({"snippet": "old"}).encode(), content_type="application/json")

    # Manually set the blob key on the row
    async def _set_key(session):
        result = await session.execute(
            select(Finding).where(Finding.tool == _TOOL, Finding.org == org, Finding.identity_key == key)
        )
        found = result.scalars().first()
        if found:
            found.detail_blob_key = prior_blob_key
    run_db(_set_key)

    _run_scan(org, [{"key": key, "detail": _LEAN_DETAIL}])

    finding = _fetch_finding(org, key)
    assert finding is not None
    assert finding.detail_blob_key is None
    assert download_json(prior_blob_key) is None


# ---------------------------------------------------------------------------
# Branch: dismissed existing finding
# ---------------------------------------------------------------------------

def test_dismissed_prev_fat_detail_creates_blob(s3_endpoint):
    """Dismissed finding that reappears: fat detail is correctly offloaded."""
    org = "lifecycle-blob-dismissed-1"
    key = "sqli-dismissed-fat"
    _clean(org)

    # Seed dismissed finding
    _seed_finding(org, key, "dismissed", _LEAN_DETAIL)
    _dismiss(org, key)

    _run_scan(org, [{"key": key, "detail": _FAT_DETAIL}])

    finding = _fetch_finding(org, key)
    assert finding is not None
    assert finding.detail_blob_key == build_blob_key(finding.id)
    assert "snippet" not in finding.detail

    blob = download_json(finding.detail_blob_key)
    assert blob is not None
    assert "snippet" in blob
