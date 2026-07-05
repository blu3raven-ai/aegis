"""Tests for the deps reachability result-ingest and its recall-safety gate.

The gate is the load-bearing invariant: an ungrounded ``no_path`` (a pre-filter
distribution-name match with no file citation) must never suppress a finding.
Each test seeds a real deps finding, mocks the uploaded results file, and asserts
the fused verdict.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from src.db.models import Asset, Finding, KevEntry
from src.dependencies import reachability_ingest
from src.dependencies.reachability_ingest import (
    REACHABILITY_JOB_TYPE,
    ingest_reachability_results,
)

_RUN_ID = "run-reach-1"
_SUPPRESSIBLE_CWE = "CWE-89"  # SQL injection — in SUPPRESSIBLE_CWES


async def _seed_finding(
    db_session, org: str, *, cve_id: str | None, cwe: str, verdict: str = "needs_verify"
) -> Finding:
    asset = Asset(
        type="repo",
        source="source_connection",
        external_ref=f"github:{org}/api",
        display_name=f"{org}/api",
    )
    db_session.add(asset)
    await db_session.flush()

    finding = Finding(
        tool="dependencies_scanning",
        asset_id=asset.id,
        identity_key=f"k-{uuid4()}",
        state="open",
        severity="high",
        detail={"cwe": cwe},
        cve_id=cve_id,
        verdict=verdict,
    )
    db_session.add(finding)
    await db_session.commit()
    return finding


async def _cleanup(db_session, org: str, cve_ids: list[str]) -> None:
    ids = (
        await db_session.execute(
            select(Asset.id).where(Asset.external_ref == f"github:{org}/api")
        )
    ).scalars().all()
    ids = list(ids)
    if ids:
        await db_session.execute(delete(Finding).where(Finding.asset_id.in_(ids)))
        await db_session.execute(delete(Asset).where(Asset.id.in_(ids)))
    for cve in cve_ids:
        await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve))
    await db_session.commit()


def _mock_upload(monkeypatch, org: str, run_id: str, results: list[dict]) -> None:
    """Wire the object-store + session + blob helpers to the test fixtures."""
    key = f"{REACHABILITY_JOB_TYPE}/{org}/{run_id}/reachability-results.json"
    monkeypatch.setattr(reachability_ingest, "list_objects", lambda prefix: [key])
    monkeypatch.setattr(
        reachability_ingest,
        "download_json",
        lambda k: {"run_id": run_id, "results": results} if k == key else None,
    )
    # Fat detail moves to MinIO in prod; keep the blob helpers inert under test.
    monkeypatch.setattr(reachability_ingest, "put_detail_blob", lambda fid, fat: None)
    monkeypatch.setattr(reachability_ingest, "delete_detail_blob", lambda key: None)


def _bind_session(monkeypatch, session) -> None:
    @asynccontextmanager
    async def _cm():
        yield session

    monkeypatch.setattr(reachability_ingest, "get_session", _cm)


@pytest.mark.asyncio
async def test_grounded_no_path_suppressible_cwe_is_ruled_out(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-1000"
    finding = await _seed_finding(db_session, org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(finding.id),
        "reachability": "no_path",
        "evidence": [{"file": "app/main.py", "line": 12, "snippet": "..."}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 1
        assert finding.verdict == "ruled_out"
        assert finding._hydrated_detail["reachability"] == "no_path"
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_ungrounded_no_path_stays_visible(db_session, monkeypatch):
    """The recall-safety gate: a name-only no_path must not hide the finding."""
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-1001"
    finding = await _seed_finding(db_session, org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(finding.id),
        "reachability": "no_path",
        # Pre-filter note only — no file citation, so not citation-grounded.
        "evidence": [{"kind": "context", "note": "distribution name not imported"}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 1
        # Downgraded to unknown → stays visible, never ruled_out.
        assert finding._hydrated_detail["reachability"] == "unknown"
        assert finding.verdict == "needs_verify"
        assert finding.verdict != "ruled_out"
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_reachable_is_not_hidden(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-1002"
    finding = await _seed_finding(db_session, org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(finding.id),
        "reachability": "reachable",
        "evidence": [{"file": "svc/handler.py", "line": 3, "snippet": "call()"}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 1
        assert finding.verdict == "needs_verify"
        assert finding._hydrated_detail["reachability"] == "reachable"
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_kev_overrides_grounded_no_path(db_session, monkeypatch):
    """A KEV-listed CVE is never ruled_out, even on a grounded no_path."""
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-1003"
    finding = await _seed_finding(db_session, org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    db_session.add(KevEntry(cve_id=cve))
    await db_session.commit()
    _bind_session(monkeypatch, db_session)
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(finding.id),
        "reachability": "no_path",
        "evidence": [{"file": "app/main.py", "line": 1, "snippet": "..."}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 1
        assert finding.verdict == "needs_verify"
        assert finding.verdict != "ruled_out"
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_recommended_fix_is_surfaced(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-1004"
    finding = await _seed_finding(db_session, org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    fix = {"summary": "upgrade to 2.1.0", "patch": "bump requests"}
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(finding.id),
        "reachability": "reachable",
        "evidence": [{"file": "app/x.py", "line": 5, "snippet": "..."}],
        "recommended_fix": fix,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 1
        assert finding.recommended_fix == fix
        assert finding._hydrated_detail["recommended_fix"] == fix
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_unknown_finding_id_is_skipped(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    # Seed one asset so the org resolves to a non-empty scope, but reference a
    # finding id that does not exist.
    await _seed_finding(db_session, org, cve_id="CVE-2024-1005", cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": "999999999",
        "reachability": "no_path",
        "evidence": [{"file": "app/main.py", "line": 1}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 0
    finally:
        await _cleanup(db_session, org, ["CVE-2024-1005"])


@pytest.mark.asyncio
async def test_finding_outside_org_scope_is_not_updated(db_session, monkeypatch):
    """BOLA guard: a result naming a finding in another org's scope is ignored."""
    org = f"acme-{uuid4().hex[:8]}"
    other_org = f"evil-{uuid4().hex[:8]}"
    cve = "CVE-2024-1006"
    victim = await _seed_finding(db_session, other_org, cve_id=cve, cwe=_SUPPRESSIBLE_CWE)
    # Give the attacker org a non-empty scope so the guard, not an empty scope,
    # is what rejects the cross-tenant id.
    await _seed_finding(db_session, org, cve_id="CVE-2024-1099", cwe=_SUPPRESSIBLE_CWE)
    _bind_session(monkeypatch, db_session)
    # Attacker's run is scoped to `org`, but names the victim's finding id.
    _mock_upload(monkeypatch, org, _RUN_ID, [{
        "finding_id": str(victim.id),
        "reachability": "no_path",
        "evidence": [{"file": "app/main.py", "line": 1, "snippet": "..."}],
        "recommended_fix": None,
    }])
    try:
        count = await ingest_reachability_results(org, _RUN_ID)
        assert count == 0
        assert victim.verdict == "needs_verify"  # untouched
    finally:
        await _cleanup(db_session, org, [])
        await _cleanup(db_session, other_org, [cve])
