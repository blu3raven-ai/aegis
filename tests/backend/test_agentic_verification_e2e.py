"""End-to-end test for the v0.2 agentic verification flow.

Covers the chain that PRs #475-#478 wired together:

  1. Admin configures the BYO LLM key via the settings service
  2. _dispatch_scanner_jobs reads the config and injects LLM_* env into
     the runner job
  3. Runner posts findings with verdict / evidence_json / exploit_chain
     populated; upsert_finding promotes them to typed columns
  4. The scan detail's verification_summary aggregate sees them

Uses the testcontainer-backed Postgres from tests/backend/conftest.py via
the same sync run_db pattern as the rest of the integration suite.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from uuid import uuid4

from cryptography.fernet import Fernet

os.environ.setdefault("AEGIS_SECRET_ENCRYPTION_KEY", Fernet.generate_key().decode())

from sqlalchemy import delete as sa_delete, select  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402

from src.db.helpers import run_db  # noqa: E402
from src.db.models import (  # noqa: E402
    Asset,
    Finding,
    FindingEvent,
    LlmConfig,
    LlmUsageDaily,
    ScanRun,
)
from src.scans.service import _dispatch_scanner_jobs  # noqa: E402
from src.settings.llm import LlmConfigUpsert, fetch_llm_config, upsert_llm_config  # noqa: E402
from src.shared.finding_queries import upsert_finding  # noqa: E402


def _seed_asset(external_ref: str, display_name: str) -> str:
    """Insert a synthetic Asset row, return its id."""
    asset_id = str(uuid4())

    async def _q(session: AsyncSession) -> None:
        session.add(
            Asset(
                id=asset_id,
                type="repo",
                source="source_connection",
                external_ref=external_ref,
                display_name=display_name,
            )
        )

    run_db(_q)
    return asset_id


def _ingest_verified_finding(asset_id: str, identity: str) -> int:
    """Mirror what the backend's findings-ingestion handler does for runner-posted
    findings that carry verdict / evidence / exploit_chain / verification_metadata."""

    runner_detail = {
        "ruleId": "python.lang.security.eval",
        "filePath": "app.py",
        "startLine": 10,
        "verdict": "confirmed",
        "evidence_json": [
            {
                "file": "app.py",
                "line": 10,
                "snippet": "eval(user_input)",
                "kind": "sink",
            }
        ],
        "exploit_chain": "http_request -> eval",
        "verification_metadata": {
            "model": "claude-sonnet-4-6",
            "tokens_in": 412,
            "tokens_out": 88,
            "prompt_hashes": ["a1b2c3"],
        },
    }

    async def _q(session: AsyncSession) -> int:
        finding = await upsert_finding(
            session,
            tool="code_scanning",
            asset_id=asset_id,
            org="acme-org",
            repo="acme-org/svc",
            identity_key=identity,
            state="open",
            severity="high",
            detail=runner_detail,
            engine="semgrep",
        )
        await session.flush()
        return finding.id

    return run_db(_q)


def _record_scan_event(finding_id: int, scan_id: str) -> None:
    async def _q(session: AsyncSession) -> None:
        session.add(
            FindingEvent(
                finding_id=finding_id,
                from_state=None,
                to_state="open",
                triggered_by="scan",
                actor=f"{scan_id}:code_scanning",
            )
        )

    run_db(_q)


def _insert_scan_run(scan_id: str, asset_id: str) -> None:
    async def _q(session: AsyncSession) -> None:
        session.add(
            ScanRun(
                id=scan_id,
                tool="pre_release",
                asset_id=asset_id,
                status="completed",
                metadata_json={
                    "repo_id": "acme-org/svc",
                    "scanner_types": ["code_scanning"],
                },
                started_at=datetime.now(timezone.utc),
                finished_at=datetime.now(timezone.utc),
            )
        )

    run_db(_q)


def _read_finding(finding_id: int) -> Finding:
    async def _q(session: AsyncSession) -> Finding:
        return (
            await session.execute(select(Finding).where(Finding.id == finding_id))
        ).scalar_one()

    return run_db(_q)


def _cleanup(asset_id: str, scan_id: str, finding_id: int) -> None:
    async def _q(session: AsyncSession) -> None:
        await session.execute(sa_delete(ScanRun).where(ScanRun.id == scan_id))
        await session.execute(
            sa_delete(FindingEvent).where(FindingEvent.finding_id == finding_id)
        )
        await session.execute(sa_delete(Finding).where(Finding.id == finding_id))
        await session.execute(sa_delete(Asset).where(Asset.id == asset_id))
        await session.execute(sa_delete(LlmConfig).where(LlmConfig.org_id == "default"))
        await session.execute(
            sa_delete(LlmUsageDaily).where(LlmUsageDaily.org_id == "default")
        )

    run_db(_q)


def test_configure_llm_then_findings_persist_verdict(monkeypatch):
    """Config → dispatch env → ingest → scan summary, end to end."""
    from src.scans import service as scans_service

    # apply_finding_mappings selects from compliance_control_mappings which
    # this test DB's bare _create_tables() doesn't provision. The compliance
    # surface isn't part of the verification flow under test, so stub it out.
    async def _noop_mapper(_session, _finding):
        return None

    monkeypatch.setattr(
        "src.compliance.auto_mapper.apply_finding_mappings", _noop_mapper
    )

    # ── 1. Configure an LLM key ─────────────────────────────────────────────
    upsert_llm_config(
        LlmConfigUpsert(
            org_id="default",
            api_key="sk-test-e2e",
            api_base_url="https://api.example.ai/v1",
            model="claude-sonnet-4-6",
            scan_token_budget=200_000,
            daily_token_budget=1_000_000,
            enabled=True,
        )
    )
    cfg = fetch_llm_config("default")
    assert cfg is not None and cfg.enabled

    # ── 2. Dispatch a scan, capture the env injected into the runner job ───
    captured: list[dict] = []

    def _fake_create_job(*, job_type, org, run_id, env_vars):
        captured.append({"job_type": job_type, "run_id": run_id, "env_vars": env_vars})

    monkeypatch.setattr("src.runner.jobs.create_job", _fake_create_job)

    scan_id = f"scan-{uuid4().hex[:8]}"
    _dispatch_scanner_jobs(
        scan_id=scan_id,
        repo_id="acme-org/svc",
        commit_sha="abc1234",
        scanners=["code_scanning"],
        org="acme-org",
    )

    assert len(captured) == 1
    env = captured[0]["env_vars"]
    assert env["LLM_API_KEY"] == "sk-test-e2e"
    assert env["LLM_API_BASE_URL"] == "https://api.example.ai/v1"
    assert env["LLM_API_MODEL"] == "claude-sonnet-4-6"
    assert env["LLM_TOKEN_BUDGET_PER_SCAN"] == "200000"
    assert env["LLM_DAILY_REMAINING"].isdigit()

    # ── 3. Simulate the runner posting back a verified finding ─────────────
    asset_id = _seed_asset(
        external_ref=f"github:acme-org/svc-{uuid4().hex[:8]}",
        display_name=f"acme-org/svc-{uuid4().hex[:8]}",
    )
    identity = f"e2e-verified-{uuid4()}"
    finding_id = _ingest_verified_finding(asset_id, identity)
    _record_scan_event(finding_id, scan_id)
    _insert_scan_run(scan_id, asset_id)

    try:
        # ── 4. Verify the verdict columns were promoted from `detail` ──────
        reread = _read_finding(finding_id)
        assert reread.verdict == "confirmed"
        assert reread.exploit_chain == "http_request -> eval"
        assert reread.evidence_json[0]["snippet"] == "eval(user_input)"
        assert reread.verification_metadata["tokens_in"] == 412
        assert reread.verification_metadata["model"] == "claude-sonnet-4-6"

        # ── 5. Scan detail returns the aggregate ───────────────────────────
        import asyncio

        detail = asyncio.run(
            scans_service.get_scan(scan_id=scan_id, asset_id=None)
        )
        assert detail is not None
        summary = detail.verification_summary
        assert summary is not None
        assert summary["confirmed"] == 1
        assert summary["needs_verify"] == 0
        assert summary["ruled_out"] == 0
        assert summary["tokens_in"] == 412
        assert summary["tokens_out"] == 88
        assert summary["model"] == "claude-sonnet-4-6"
    finally:
        _cleanup(asset_id, scan_id, finding_id)
