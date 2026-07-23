"""Backend enqueue helper for container CVE enrichment verification jobs.

Container findings are built backend-side (SBOM + OSV match); the runner does no
container vulnerability match. This helper ships the CVE-bearing findings to a
runner ``container_verification`` job that runs the LLM enrichment verifier (no
repo clone — the advisory + package/image metadata is all it needs) and writes
results the backend fuses in verify_ingest.

The job is only created when a BYO LLM is enabled (mirror of the reachability
dispatch gate): the enrichment verifier is LLM-client-only, so a hosted-Argus-only
org enqueues nothing.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

CONTAINER_VERIFY_JOB_TYPE = "container_verification"
_LLM_CONFIG_KEY = "default"


def _build_verification_env() -> dict[str, str]:
    """Build LLM env-var block for the runner job.

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
            "LLM_TRANSPORT":             llm_cfg.transport or "auto",
        })
        if llm_cfg.anthropic_base_url:
            env["LLM_ANTHROPIC_BASE_URL"] = llm_cfg.anthropic_base_url

    return env


@dataclass(frozen=True)
class ContainerVerifyFinding:
    finding_id: str
    asset_id: str
    external_ref: str
    package: str
    version: str
    cve: str | None
    image_name: str = ""
    image_tag: str = ""


def enqueue_container_verify_jobs(
    *, org: str, run_id: str, findings: list[ContainerVerifyFinding]
) -> list[str]:
    """One verification job per run for the CVE-bearing container findings.

    No repo clone — the finding metadata is all the enrichment verifier needs.
    Returns [] when BYO LLM is disabled or no CVE-bearing finding qualifies.
    """
    verification_env = _build_verification_env()
    if not verification_env:
        return []
    targets = [f for f in findings if f.cve]
    if not targets:
        return []

    from src.runner.jobs import create_job

    payload = [
        {
            "finding_id": t.finding_id,
            "packageName": t.package,
            "packageVersion": t.version,
            "cve": t.cve,
            "imageName": t.image_name,
            "imageTag": t.image_tag,
        }
        for t in targets
    ]
    env_vars = {
        "ORG_LABEL": org,
        "RUN_ID": run_id,
        "CONTAINER_VERIFY_TARGETS": json.dumps(payload),
        **verification_env,
    }
    job = create_job(
        job_type=CONTAINER_VERIFY_JOB_TYPE, org=org, run_id=run_id, env_vars=env_vars
    )
    job_id = job["id"] if isinstance(job, dict) else job
    return [job_id]
