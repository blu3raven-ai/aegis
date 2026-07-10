"""Tests for the container verification result-ingest and verdict fuse.

The verdict fuse never emits 'ruled_out' — container images are ephemeral and
there is no reachability signal to justify suppression. These tests verify the
fuse logic, the detail-blob write path, and the BOLA scope guard.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
from sqlalchemy import delete, select

from src.containers import verify_ingest
from src.containers.verify_ingest import (
    _apply_results,
    compute_container_verdict,
    ingest_container_verify_results,
)
from src.db.models import Asset, Finding, KevEntry


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------

async def _seed_finding(
    db_session,
    org: str,
    *,
    cve_id: str | None = "CVE-2024-9999",
    severity: str = "high",
    verdict: str = "needs_verify",
) -> Finding:
    asset = Asset(
        type="image",
        source="source_connection",
        external_ref=f"ghcr:{org}/myimage:latest",
        display_name=f"{org}/myimage",
    )
    db_session.add(asset)
    await db_session.flush()

    finding = Finding(
        tool="container_scanning",
        asset_id=asset.id,
        identity_key=f"k-{uuid4()}",
        state="open",
        severity=severity,
        detail={"cwe": "CWE-79", "imageName": "myimage"},
        cve_id=cve_id,
        verdict=verdict,
    )
    db_session.add(finding)
    await db_session.commit()
    return finding


async def _cleanup(db_session, org: str, cve_ids: list[str]) -> None:
    ids = (
        await db_session.execute(
            select(Asset.id).where(Asset.external_ref.like(f"%:{org}/%"))
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
    """Wire the object-store + blob helpers to the test fixtures."""
    from src.containers.verify_dispatch import CONTAINER_VERIFY_JOB_TYPE

    key = f"{CONTAINER_VERIFY_JOB_TYPE}/{org}/{run_id}/container-verify-results.json"
    monkeypatch.setattr(verify_ingest, "list_objects", lambda prefix: [key])
    monkeypatch.setattr(
        verify_ingest,
        "download_json",
        lambda k: {"run_id": run_id, "results": results} if k == key else None,
    )
    monkeypatch.setattr(verify_ingest, "put_detail_blob", lambda fid, fat: None)
    monkeypatch.setattr(verify_ingest, "delete_detail_blob", lambda k: None)


def _bind_session(monkeypatch, session) -> None:
    @asynccontextmanager
    async def _cm():
        yield session

    monkeypatch.setattr(verify_ingest, "get_session", _cm)


# ---------------------------------------------------------------------------
# compute_container_verdict unit tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_compute_verdict_kev_listed_returns_confirmed(db_session):
    cve = f"CVE-2099-{uuid4().hex[:6]}"
    db_session.add(KevEntry(cve_id=cve))
    await db_session.commit()
    try:
        verdict = await compute_container_verdict(
            db_session, cve_id=cve, severity="low", cwe_raw=None
        )
        assert verdict == "confirmed"
    finally:
        await db_session.execute(delete(KevEntry).where(KevEntry.cve_id == cve))
        await db_session.commit()


@pytest.mark.asyncio
async def test_compute_verdict_high_severity_returns_confirmed(db_session):
    verdict = await compute_container_verdict(
        db_session, cve_id=None, severity="high", cwe_raw=None
    )
    assert verdict == "confirmed"
    assert verdict != "ruled_out"


@pytest.mark.asyncio
async def test_compute_verdict_low_severity_unknown_cve_never_ruled_out(db_session):
    verdict = await compute_container_verdict(
        db_session, cve_id=None, severity="low", cwe_raw=None
    )
    assert verdict != "ruled_out"


@pytest.mark.asyncio
async def test_compute_verdict_medium_with_cwe_returns_possible(db_session):
    verdict = await compute_container_verdict(
        db_session, cve_id=None, severity="medium", cwe_raw="CWE-79"
    )
    assert verdict == "possible"


# ---------------------------------------------------------------------------
# _apply_results integration tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_apply_results_sets_verification_metadata_and_verdict(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-8001"
    finding = await _seed_finding(db_session, org, cve_id=cve, severity="high")
    monkeypatch.setattr(verify_ingest, "put_detail_blob", lambda fid, fat: None)
    monkeypatch.setattr(verify_ingest, "delete_detail_blob", lambda k: None)
    try:
        count = await _apply_results(
            db_session,
            org=org,
            results=[{
                "finding_id": str(finding.id),
                "verdict": "confirmed",
                "evidence": [],
                "verification_metadata": {"impact": "RCE", "fix": "upgrade"},
            }],
        )
        assert count == 1
        assert finding.verification_metadata["impact"] == "RCE"
        assert finding.verdict is not None
        assert finding.verdict != "ruled_out"
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_apply_results_failed_target_skipped(db_session, monkeypatch):
    """A result with no 'verdict' key (failed runner target) must not alter the finding."""
    org = f"acme-{uuid4().hex[:8]}"
    cve = "CVE-2024-8002"
    finding = await _seed_finding(db_session, org, cve_id=cve)
    original_verdict = finding.verdict
    monkeypatch.setattr(verify_ingest, "put_detail_blob", lambda fid, fat: None)
    monkeypatch.setattr(verify_ingest, "delete_detail_blob", lambda k: None)
    try:
        count = await _apply_results(
            db_session,
            org=org,
            results=[{"finding_id": str(finding.id)}],  # no verdict key
        )
        assert count == 0
        assert finding.verdict == original_verdict
        assert finding.verification_metadata is None
    finally:
        await _cleanup(db_session, org, [cve])


@pytest.mark.asyncio
async def test_apply_results_bola_guard(db_session, monkeypatch):
    """A result naming a finding outside the caller org's scope is ignored."""
    org = f"acme-{uuid4().hex[:8]}"
    other_org = f"evil-{uuid4().hex[:8]}"
    victim = await _seed_finding(db_session, other_org, cve_id="CVE-2024-8003")
    # Give attacker org a non-empty scope.
    await _seed_finding(db_session, org, cve_id="CVE-2024-8099")
    monkeypatch.setattr(verify_ingest, "put_detail_blob", lambda fid, fat: None)
    monkeypatch.setattr(verify_ingest, "delete_detail_blob", lambda k: None)
    try:
        count = await _apply_results(
            db_session,
            org=org,
            results=[{
                "finding_id": str(victim.id),
                "verdict": "confirmed",
                "evidence": [],
                "verification_metadata": {"impact": "pwned"},
            }],
        )
        assert count == 0
        assert victim.verification_metadata is None  # untouched
    finally:
        await _cleanup(db_session, org, [])
        await _cleanup(db_session, other_org, ["CVE-2024-8003"])
        await _cleanup(db_session, org, ["CVE-2024-8099"])


# ---------------------------------------------------------------------------
# ingest_container_verify_results (full end-to-end with mocked object store)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ingest_full_pipeline(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    run_id = "run-cv-1"
    cve = "CVE-2024-8004"
    finding = await _seed_finding(db_session, org, cve_id=cve, severity="critical")
    _mock_upload(monkeypatch, org, run_id, [{
        "finding_id": str(finding.id),
        "verdict": "confirmed",
        "evidence": [{"note": "base image EOL"}],
        "verification_metadata": {"impact": "full compromise", "fix": "rebuild"},
    }])
    _bind_session(monkeypatch, db_session)
    try:
        count = await ingest_container_verify_results(org, run_id)
        assert count == 1
        assert finding.verification_metadata["impact"] == "full compromise"
        assert finding.verdict != "ruled_out"
    finally:
        await _cleanup(db_session, org, [cve])
