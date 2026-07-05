"""Backend enqueue helper for deps reachability jobs.

Dependency findings are built backend-side from the SBOM + OSV mirror; the
runner deps scanner never performs the vulnerability match. This helper builds
the runner job that will clone the repo and compute call-path reachability for
each CVE-bearing dependency finding, so the backend ``deps_verdict`` fuse can
read ``detail.reachability``.

Reachability analysis needs an LLM to trace call paths, so the job is only
created when a BYO ``LLM_*`` model is enabled. (Hosted Argus does not enable
reachability — the runner verifier has no Argus route; see _build_verification_env.)
When it is not enabled there is nothing to run and no job is enqueued.

Wired into the live dependency ingest path in #1291.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

REACHABILITY_JOB_TYPE = "dependencies_reachability"

# The org's BYO LLM config lives under the default config slot — the same
# record that routes scan verification.
_LLM_CONFIG_KEY = "default"


@dataclass(frozen=True)
class ReachabilityFinding:
    """One persisted dependency finding as a reachability candidate.

    ``finding_id``/``asset_id``/``external_ref`` are known post-upsert — the
    asset's ``external_ref`` resolves the repo clone URL. ``package``/
    ``version``/``ecosystem``/``cve`` describe the vulnerable dependency the
    runner must trace (these map to the built finding's
    ``dependency.package.{name,ecosystem}``, ``current_version`` and
    ``security_advisory.cve_id``).
    """
    finding_id: str
    asset_id: str
    external_ref: str
    package: str
    version: str
    ecosystem: str
    cve: str | None
    malicious: bool = False


def _build_verification_env() -> dict[str, str]:
    """Verification env for a reachability job.

    Ships the BYO ``LLM_*`` config when a BYO LLM is enabled; empty otherwise.
    Reachability tracing is LLM-client-only — ``verify_deps_finding`` has no
    Argus route — so a hosted-Argus-only connection does NOT enable reachability.
    Enqueueing an Argus-only org would just strand a clone+job the runner can't
    run; supporting Argus for reachability is a separate follow-up.

    DRY: share with scans/service.py::_dispatch_scanner_jobs. Kept as a thin,
    audit-free copy here so the reachability enqueue does not inherit the scan
    path's scan-lifecycle side effects.
    """
    from src.settings.llm.service import fetch_llm_config
    from src.settings.llm.usage import daily_remaining

    env: dict[str, str] = {}

    llm_cfg = fetch_llm_config(_LLM_CONFIG_KEY)
    if llm_cfg and llm_cfg.enabled:
        env.update({
            "LLM_API_KEY":               llm_cfg.api_key,
            "LLM_API_BASE_URL":          llm_cfg.api_base_url,
            "LLM_API_MODEL":             llm_cfg.model,
            "LLM_TOKEN_BUDGET_PER_SCAN": str(llm_cfg.scan_token_budget),
            "LLM_DAILY_REMAINING":       str(daily_remaining(
                org_id=_LLM_CONFIG_KEY,
                daily_budget=llm_cfg.daily_token_budget,
            )),
        })

    return env


def enqueue_reachability_jobs(
    *,
    org: str,
    run_id: str,
    findings: list[ReachabilityFinding],
) -> list[str]:
    """Enqueue one reachability job per asset for the CVE-bearing deps findings.

    Returns the created job ids. Returns an empty list when verification is
    disabled (no model to run reachability) or no CVE-bearing finding qualifies.
    """
    verification_env = _build_verification_env()
    if not verification_env:
        return []

    # Reachability only matters for vulnerabilities; skip components with no
    # advisory id to trace, and malicious packages (a compromised package is a
    # removal issue, not a reachability question).
    targets = [f for f in findings if f.cve and not f.malicious]
    if not targets:
        return []

    from src.runner.jobs import create_job
    from src.scans.service import _resolve_repo_dispatch_target
    from src.shared.config import get_token_for_org

    token = get_token_for_org(org) or ""

    # Group by asset so a job clones a repo once and traces all its vulnerable
    # dependencies in a single pass.
    by_asset: dict[str, list[ReachabilityFinding]] = {}
    for t in targets:
        by_asset.setdefault(t.asset_id, []).append(t)

    job_ids: list[str] = []
    for asset_id, asset_targets in by_asset.items():
        source_type, _owner, _name, clone_url = _resolve_repo_dispatch_target(
            asset_targets[0].external_ref
        )

        payload = [
            {
                "finding_id": t.finding_id,
                "package": t.package,
                "version": t.version,
                "ecosystem": t.ecosystem,
                "cve": t.cve,
            }
            for t in asset_targets
        ]
        env_vars: dict[str, str] = {
            "GIT_TOKEN":            token,
            "GIT_REPOS":            clone_url,
            "ORG_LABEL":            org,
            "RUN_ID":               run_id,
            "REACHABILITY_TARGETS": json.dumps(payload),
            **verification_env,
        }
        if source_type:
            env_vars["SOURCE_TYPE"] = source_type

        job = create_job(
            job_type=REACHABILITY_JOB_TYPE, org=org, run_id=run_id, env_vars=env_vars,
        )
        job_id = job["id"] if isinstance(job, dict) else job
        job_ids.append(job_id)
        logger.info(
            "Enqueued reachability job %s for asset %s (%d targets, run %s)",
            job_id, asset_id, len(asset_targets), run_id,
        )

    return job_ids
