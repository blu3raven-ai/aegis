"""Ingest container verification results and fuse a verdict onto container findings.

The runner uploads ``container-verify-results.json`` per verification job. This
module reads those results, computes a KEV + severity + CWE verdict (no
reachability axis — container images are ephemeral and the signal is absent),
and writes the enriched metadata back onto the matching ``container_scanning``
Finding rows.

Mirrors ``backend/src/dependencies/reachability_ingest.py`` structurally; the
key difference is the verdict fuse never emits ``ruled_out`` because there is no
grounded reachability signal to justify suppression.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.authz.enforcement.scope import resolve_asset_ids_for_org
from src.containers.verify_dispatch import CONTAINER_VERIFY_JOB_TYPE
from src.db.engine import get_session
from src.db.models import Finding, KevEntry
from src.shared.finding_detail_blob import (
    delete_detail_blob,
    hydrate_detail,
    put_detail_blob,
    split_detail,
)
from src.shared.object_store import download_json, list_objects

logger = logging.getLogger(__name__)

_TOOL = "container_scanning"
_RESULTS_FILENAME = "container-verify-results.json"


async def compute_container_verdict(
    session: AsyncSession,
    *,
    cve_id: str | None,
    severity: str | None,
    cwe_raw: Any,
) -> str:
    """Container CVE verdict: KEV + severity + CWE, no reachability.

    Container images are gone at verify-time, so there is no reachability signal
    and we never suppress: the worst case is 'possible', never 'ruled_out'.

    - KEV-listed → confirmed (actively exploited in the wild).
    - else critical/high severity → confirmed.
    - else medium with a known CWE → possible.
    - else → needs_verify.
    """
    if cve_id:
        kev_row = await session.execute(
            select(KevEntry.cve_id).where(KevEntry.cve_id == cve_id)
        )
        if kev_row.scalar() is not None:
            return "confirmed"

    sev = (severity or "").lower()
    if sev in ("critical", "high"):
        return "confirmed"

    # Normalise CWE input the same way compute_deps_verdict does.
    if isinstance(cwe_raw, list):
        cwes = [str(c).strip() for c in cwe_raw if str(c).strip()]
    elif isinstance(cwe_raw, str) and cwe_raw.strip():
        cwes = [cwe_raw.strip()]
    else:
        cwes = []

    if sev == "medium" and cwes:
        return "possible"

    return "needs_verify"


def _load_results(org: str, run_id: str) -> list[dict[str, Any]]:
    """Read and flatten container verification results uploaded for an org/run."""
    prefix = f"{CONTAINER_VERIFY_JOB_TYPE}/{org}/{run_id}/"
    out: list[dict[str, Any]] = []
    for key in list_objects(prefix):
        if not key.endswith(_RESULTS_FILENAME):
            continue
        payload = download_json(key)
        if not payload:
            continue
        for result in payload.get("results", []):
            if isinstance(result, dict) and result.get("finding_id") is not None:
                out.append(result)
    return out


async def _apply_results(
    session: AsyncSession, *, org: str, results: list[dict[str, Any]]
) -> int:
    """Update in-scope container findings from the parsed verification results."""
    asset_ids = await resolve_asset_ids_for_org(session, org)
    if not asset_ids:
        return 0

    # Never trust a runner-supplied finding_id blindly: match by id AND the
    # org's own asset scope at the SQL layer so a foreign id can't be updated.
    by_id: dict[int, dict[str, Any]] = {}
    for result in results:
        try:
            finding_id = int(result["finding_id"])
        except (TypeError, ValueError):
            continue
        by_id[finding_id] = result  # last write wins on duplicate id
    if not by_id:
        return 0

    rows = (
        await session.execute(
            select(Finding).where(
                Finding.tool == _TOOL,
                Finding.id.in_(by_id.keys()),
                Finding.asset_id.in_(asset_ids),
            )
        )
    ).scalars().all()

    updated = 0
    for finding in rows:
        result = by_id.get(finding.id)
        if result is None:
            continue
        # Skip failed targets that the runner couldn't verify (no verdict key).
        if "verdict" not in result or result["verdict"] is None:
            continue

        vm = result.get("verification_metadata") or {}
        evidence = result.get("evidence") or []

        full = dict(hydrate_detail(finding))
        # Merge verification metadata into the hydrated detail.
        full["verification_metadata"] = vm
        full["evidence"] = evidence

        verdict = await compute_container_verdict(
            session,
            cve_id=finding.cve_id,
            severity=finding.severity,
            cwe_raw=full.get("cwe"),
        )

        lean, fat = split_detail(_TOOL, full)
        finding.detail = lean
        if fat:
            finding.detail_blob_key = put_detail_blob(finding.id, fat)
        elif finding.detail_blob_key:
            delete_detail_blob(finding.detail_blob_key)
            finding.detail_blob_key = None
        finding._hydrated_detail = full

        finding.verification_metadata = vm
        finding.evidence = evidence
        finding.verdict = verdict
        finding.updated_at = datetime.now(timezone.utc)
        updated += 1

    return updated


async def ingest_container_verify_results(org: str, run_id: str) -> int:
    """Fuse a container verification run's uploaded results into container findings.

    Returns the number of findings updated. Findings whose IDs are unknown or
    outside the org's asset scope are silently skipped.
    """
    if not org or not run_id:
        return 0
    results = _load_results(org, run_id)
    if not results:
        return 0
    async with get_session() as session:
        return await _apply_results(session, org=org, results=results)
