"""Go-live wiring tests for the deps reachability feature.

Two wire points are covered:
  1. ``ingest_dependencies_from_minio`` re-queries the just-persisted CVE-bearing
     deps findings and hands them to ``enqueue_reachability_jobs`` (best-effort:
     a disabled provider is a no-op, an enqueue error never sinks the scan).
  2. ``_ingest_from_minio`` bridges the async ``ingest_reachability_results`` from
     its sync background-thread context on a ``dependencies_reachability`` job.

The SBOM index, OSV match, advisory enrich and run-status writes are stubbed so
the tests exercise only the new wiring, not the whole ingest pipeline.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlalchemy import delete, select

import src.dependencies.reachability_dispatch as reachability_dispatch
import src.dependencies.scanner as scanner
import src.runner.router as runner_router
from src.db.models import Asset, Finding


async def _seed_deps_finding(db_session, org: str) -> tuple[Asset, Finding]:
    """Persist one CVE-bearing dependencies finding on a fresh repo asset."""
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
        detail={"ecosystem": "PyPI"},
        cve_id="CVE-2024-9001",
        package_name="requests",
        package_version="2.0.0",
        verdict="needs_verify",
    )
    db_session.add(finding)
    await db_session.commit()
    return asset, finding


async def _cleanup(db_session, org: str) -> None:
    ids = (
        await db_session.execute(
            select(Asset.id).where(Asset.external_ref == f"github:{org}/api")
        )
    ).scalars().all()
    ids = list(ids)
    if ids:
        await db_session.execute(delete(Finding).where(Finding.asset_id.in_(ids)))
        await db_session.execute(delete(Asset).where(Asset.id.in_(ids)))
    await db_session.commit()


def _stub_ingest_pipeline(monkeypatch, assets: dict[str, str]) -> list[dict]:
    """Stub the SBOM/match/enrich/run-status boundaries; capture run updates."""
    monkeypatch.setattr(
        scanner, "_ingest_sboms_from_minio",
        lambda org, run_id, source_type, prefix: dict(assets),
    )

    async def _no_match(session, **kw):
        return []

    monkeypatch.setattr(
        "src.osv.sca_findings.build_backend_match_findings", _no_match
    )
    monkeypatch.setattr(scanner, "read_app_config", lambda: {})
    monkeypatch.setattr(
        scanner, "enrich_findings_with_advisory_data",
        lambda findings, **kw: findings,
    )

    run_updates: list[dict] = []
    monkeypatch.setattr(
        scanner, "update_dependencies_run",
        lambda org, run_id, patch: run_updates.append(patch),
    )
    monkeypatch.setattr("src.storage.list_dependencies_runs", lambda org: [])
    return run_updates


@pytest.mark.asyncio
async def test_ingest_enqueues_reachability_for_cve_finding(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    asset, finding = await _seed_deps_finding(db_session, org)
    _stub_ingest_pipeline(monkeypatch, {asset.id: asset.external_ref})

    captured: dict = {}

    def _fake_enqueue(*, org, run_id, findings):
        captured["org"] = org
        captured["run_id"] = run_id
        captured["findings"] = findings
        return ["job-1"]

    monkeypatch.setattr(reachability_dispatch, "enqueue_reachability_jobs", _fake_enqueue)

    try:
        scanner.ingest_dependencies_from_minio(org, "run-1", source_type="github")

        assert captured["org"] == org
        assert captured["run_id"] == "run-1"
        assert len(captured["findings"]) == 1
        rf = captured["findings"][0]
        assert rf.finding_id == str(finding.id)
        assert rf.asset_id == asset.id
        assert rf.external_ref == asset.external_ref
        assert rf.package == "requests"
        assert rf.version == "2.0.0"
        assert rf.ecosystem == "PyPI"
        assert rf.cve == "CVE-2024-9001"
    finally:
        await _cleanup(db_session, org)


@pytest.mark.asyncio
async def test_ingest_no_enqueue_when_verification_disabled(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    asset, _ = await _seed_deps_finding(db_session, org)
    run_updates = _stub_ingest_pipeline(monkeypatch, {asset.id: asset.external_ref})

    # Drive the real enqueue helper with verification disabled: no LLM config and
    # (in a fresh test DB) no Argus connection → env is empty → no job created.
    monkeypatch.setattr("src.settings.llm.service.fetch_llm_config", lambda key: None)
    created: list[dict] = []
    monkeypatch.setattr(
        "src.runner.jobs.create_job",
        lambda **kw: created.append(kw) or {"id": "job-x"},
    )

    try:
        scanner.ingest_dependencies_from_minio(org, "run-2", source_type="github")

        assert created == []
        # The scan still completes normally.
        assert any(p.get("status") == "completed" for p in run_updates)
    finally:
        await _cleanup(db_session, org)


@pytest.mark.asyncio
async def test_ingest_survives_enqueue_error(db_session, monkeypatch):
    org = f"acme-{uuid4().hex[:8]}"
    asset, _ = await _seed_deps_finding(db_session, org)
    run_updates = _stub_ingest_pipeline(monkeypatch, {asset.id: asset.external_ref})

    def _boom(*, org, run_id, findings):
        raise RuntimeError("enqueue exploded")

    monkeypatch.setattr(reachability_dispatch, "enqueue_reachability_jobs", _boom)

    try:
        # Must not raise — the enqueue is best-effort.
        scanner.ingest_dependencies_from_minio(org, "run-3", source_type="github")
        assert any(p.get("status") == "completed" for p in run_updates)
    finally:
        await _cleanup(db_session, org)


def test_ingest_from_minio_bridges_reachability_job(monkeypatch):
    """A dependencies_reachability job drives the async ingest via asyncio.run."""
    calls: list[tuple[str, str]] = []

    async def _fake_ingest(org: str, run_id: str) -> int:
        calls.append((org, run_id))
        return 3

    monkeypatch.setattr(
        "src.dependencies.reachability_ingest.ingest_reachability_results",
        _fake_ingest,
    )
    # Isolate the surrounding run-status / event / notification side effects.
    monkeypatch.setattr(runner_router, "_read_run_record", lambda *a, **k: None)
    monkeypatch.setattr(runner_router, "_update_run_status", lambda *a, **k: None)

    class _Bus:
        def publish_sync(self, event):
            return None

    monkeypatch.setattr(runner_router, "get_event_bus", lambda: _Bus())
    monkeypatch.setattr(
        "src.notifications.emitter.notify_scan_completed", lambda *a, **k: None
    )

    job = {
        "id": "j1",
        "org": "acme",
        "runId": "run-reach",
        "jobType": "dependencies_reachability",
        "envVars": {},
    }
    runner_router._ingest_from_minio(job)

    assert calls == [("acme", "run-reach")]
