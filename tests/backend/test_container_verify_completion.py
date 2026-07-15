"""Wiring test: a completed container_verification job drives ingest_container_verify_results."""
from __future__ import annotations

import src.runner.router as runner_router


def test_ingest_from_minio_bridges_container_verify_job(monkeypatch):
    """A container_verification job drives the async ingest via asyncio.run."""
    calls: list[tuple[str, str]] = []

    async def _fake_ingest(org: str, run_id: str) -> int:
        calls.append((org, run_id))
        return 5

    monkeypatch.setattr(
        "src.containers.verify_ingest.ingest_container_verify_results",
        _fake_ingest,
    )
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
        "org": "acme-org",
        "runId": "verify-run-1",
        "jobType": "container_verification",
        "envVars": {},
    }
    runner_router._ingest_from_minio(job)

    assert calls == [("acme-org", "verify-run-1")]
