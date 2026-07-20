"""Deep-audit — ingest findings from the object store after runner completion."""
from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.deep_audit.lifecycle import deep_audit_hooks
from src.shared.lifecycle import ScanContext, apply_lifecycle as _apply_lifecycle
from src.storage import update_deep_audit_run

logger = logging.getLogger(__name__)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def ingest_deep_audit_from_minio(org: str, run_id: str, source_type: str | None = None) -> None:
    """Ingest deep-audit results from the object store after runner completion."""
    from src.shared.object_store import find_findings_jsonl
    from src.deep_audit.ingest import read_deep_audit_findings

    data = find_findings_jsonl(f"deep_audit/{org}/{run_id}/")
    all_findings: list[dict[str, Any]] = []

    if data is None:
        logger.warning("No deep-audit output for %s/%s", org, run_id)
        update_deep_audit_run(org, run_id, {"status": "failed", "finishedAt": now_iso(), "error": "No output files found"})
        return

    if data:
        with tempfile.NamedTemporaryFile(mode="wb", suffix=".jsonl", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            all_findings = read_deep_audit_findings(Path(tmp_path))
        finally:
            os.unlink(tmp_path)

    # Skip lifecycle on empty results — could be scanner errors, not truly 0 findings
    new_findings: list[dict[str, Any]] = []
    if all_findings:
        from src.runner.jobs import git_repos_for_run
        ctx = ScanContext(
            tool="deep_audit", org=org, run_id=run_id, source_type=source_type,
            git_repos=git_repos_for_run(run_id),
        )
        new_findings = _apply_lifecycle(deep_audit_hooks, ctx, all_findings)

        try:
            from src.settings.llm.usage import record_usage_from_findings
            record_usage_from_findings(all_findings)
        except Exception:
            logger.warning("Failed to record LLM usage from deep-audit ingest", exc_info=True)

    if new_findings:
        try:
            from src.notifications.emitter import notify_new_critical_findings
            notify_new_critical_findings("deep_audit", org, new_findings)
        except Exception:
            logger.warning("Failed to emit new finding notifications", exc_info=True)

        from src.shared.event_emit_helpers import emit_finding_created
        for finding in new_findings:
            emit_finding_created(
                finding=finding,
                scanner_type="deep_audit",
                source_component="deep_audit.scanner",
            )

    # Guard against race: don't overwrite a concurrent cancellation
    from src.storage import list_deep_audit_runs
    current = next((r for r in list_deep_audit_runs(org) if r.get("id") == run_id), None)
    if current and current.get("status") == "cancelled":
        logger.info("Skipping completion — run %s already cancelled", run_id)
        return

    update_deep_audit_run(org, run_id, {
        "status": "completed",
        "finishedAt": now_iso(),
        "findingsCount": len(all_findings),
        "progress": {"percent": 100, "stage": "completed"},
    })
