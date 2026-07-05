"""Ingest runner reachability results and fuse them into deps findings.

The reachability job clones a repo, judges each CVE-bearing dependency finding's
call-path reachability, and uploads one ``reachability-results.json`` per asset.
This module reads those results and recomputes each finding's verdict through the
recall-safe ``deps_verdict`` fuse.

Recall safety: the runner's cheap import pre-filter can emit ``no_path`` from a
distribution-name match alone, but PyPI import names often differ from the
distribution name (e.g. ``PyYAML`` imports as ``yaml``), so an ungrounded
``no_path`` is not trustworthy. A ``no_path`` may only suppress a finding when it
is citation-grounded — its evidence carries a real file citation from the
LLM-judged path. An ungrounded ``no_path`` is downgraded to ``unknown`` so a real
vulnerability is never hidden on a name-only guess.

This is the pure ingest function; wiring it into the job-complete handler is a
separate step and deliberately not done here.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.authz.enforcement.scope import resolve_asset_ids_for_org
from src.db.engine import get_session
from src.db.models import Finding
from src.dependencies.reachability_dispatch import REACHABILITY_JOB_TYPE
from src.shared.finding_detail_blob import (
    delete_detail_blob,
    hydrate_detail,
    put_detail_blob,
    split_detail,
)
from src.shared.finding_queries import compute_deps_verdict
from src.shared.object_store import download_json, list_objects

logger = logging.getLogger(__name__)

_TOOL = "dependencies_scanning"
# Mirrors the runner's output filename (backend can't import the runner package).
_RESULTS_FILENAME = "reachability-results.json"


def _effective_reachability(reachability: str, evidence: list[Any] | None) -> str:
    """Downgrade an ungrounded ``no_path`` to ``unknown`` (recall-safety gate).

    A ``no_path`` may only hide a finding when it is grounded in a real file
    citation; a pre-filter ``no_path`` carries only a context note with no file.
    """
    grounded = any(isinstance(e, dict) and e.get("file") for e in (evidence or []))
    if reachability == "no_path" and not grounded:
        return "unknown"
    return reachability


def _load_results(org: str, run_id: str) -> list[dict[str, Any]]:
    """Read and flatten every reachability result uploaded for this org/run."""
    prefix = f"{REACHABILITY_JOB_TYPE}/{org}/{run_id}/"
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
    """Update in-scope deps findings from the parsed reachability results."""
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
        by_id[finding_id] = result  # last write wins on a duplicate id
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
        raw = result.get("reachability")
        if not raw:
            # A result without a label carries nothing to fuse.
            continue
        evidence = result.get("evidence") or []
        effective = _effective_reachability(raw, evidence)

        full = dict(hydrate_detail(finding))
        verdict = await compute_deps_verdict(
            session,
            reachability=effective,
            cve_id=finding.cve_id,
            cwe_raw=full.get("cwe"),
        )

        full["reachability"] = effective
        full["evidence"] = evidence
        recommended_fix = result.get("recommended_fix")
        if recommended_fix is not None:
            full["recommended_fix"] = recommended_fix

        lean, fat = split_detail(_TOOL, full)
        finding.detail = lean
        if fat:
            finding.detail_blob_key = put_detail_blob(finding.id, fat)
        elif finding.detail_blob_key:
            delete_detail_blob(finding.detail_blob_key)
            finding.detail_blob_key = None
        finding._hydrated_detail = full

        finding.evidence = evidence
        if recommended_fix is not None:
            finding.recommended_fix = recommended_fix
        finding.verdict = verdict
        finding.updated_at = datetime.now(timezone.utc)
        updated += 1

    return updated


async def ingest_reachability_results(org: str, run_id: str) -> int:
    """Fuse a reachability run's uploaded results into the deps findings.

    Returns the number of findings updated. Findings whose id is unknown or
    outside the org's asset scope are silently skipped.
    """
    if not org or not run_id:
        return 0
    results = _load_results(org, run_id)
    if not results:
        return 0
    async with get_session() as session:
        return await _apply_results(session, org=org, results=results)
