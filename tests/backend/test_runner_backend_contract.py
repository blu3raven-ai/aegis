"""Backend ↔ runner contract pin.

Asserts the runner dispatcher and backend job-type registry agree, and that
each scanner's MinIO upload prefix matches its ingest prefix. Catches silent
drift of the class that has hit this surface repeatedly:

  * #767 — backend renamed scanner tools to '_scanning' suffix; runner
    dispatcher kept the old names ('container', 'code-scanning'). Container
    + code scans crashed on the runner.
  * #772 — backend renamed the MinIO prefix to match job_type ('dependencies_scanning/');
    ingest paths still looked at 'dependencies/'. Dependency + secret scans
    failed silently with 'No output files found', SBOM history stayed empty.

The contract test runs from the backend pytest harness. The runner package
lives at the repo root (sibling to backend/), so we add it to sys.path
explicitly — backend tests don't normally see it.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Repo root is two levels up from this file: tests/backend/<here>.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

try:
    from runner.core.dispatcher import supported_types
    _RUNNER_IMPORTABLE = True
except ImportError:  # pragma: no cover
    _RUNNER_IMPORTABLE = False


pytestmark = pytest.mark.skipif(
    not _RUNNER_IMPORTABLE,
    reason="runner package not importable from backend test env",
)


def test_every_backend_job_type_is_handled_by_runner_dispatcher():
    """Every scanner the backend dispatches must have a handler on the runner.

    If you add a new scanner to backend src/scans/service.py::_SCANNER_JOB_TYPES,
    you must register it in runner/core/dispatcher.py::_SCANNERS or jobs of that
    type will fail on the runner with 'Unknown scanner type'.
    """
    from src.scans.service import _SCANNER_JOB_TYPES

    backend_emitted = set(_SCANNER_JOB_TYPES.values())
    runner_handles = set(supported_types())
    missing_on_runner = backend_emitted - runner_handles
    assert not missing_on_runner, (
        f"backend dispatches these job_type values that the runner cannot handle: "
        f"{sorted(missing_on_runner)}. Add them to runner/core/dispatcher.py "
        f"or remove them from backend/src/scans/service.py::_SCANNER_JOB_TYPES."
    )


def test_runner_minio_upload_prefix_matches_backend_ingest_prefix():
    """Runner uploads scan output under f'{job_type}/{org}/{run_id}/...' (see
    backend src/runner/router.py::presign_uploads which keys on job['jobType']).
    The backend's ingest readers must look at the SAME prefix or output is
    silently orphaned in MinIO.
    """
    import inspect
    from src.dependencies.scanner import ingest_dependencies_from_minio
    from src.secrets.scanner import ingest_secrets_from_minio
    from src.code_scanning.scanner import ingest_code_scanning_from_minio
    from src.containers.scanner import ingest_container_from_minio

    expected_prefixes = {
        "dependencies_scanning": (ingest_dependencies_from_minio, "dependencies_scanning/"),
        "secret_scanning":       (ingest_secrets_from_minio,       "secret_scanning/"),
        "code_scanning":         (ingest_code_scanning_from_minio, "code_scanning/"),
        "container_scanning":    (ingest_container_from_minio,     "container_scanning/"),
    }

    for job_type, (fn, expected) in expected_prefixes.items():
        src = inspect.getsource(fn)
        assert expected in src, (
            f"ingest function for {job_type!r} does not reference the canonical "
            f"upload prefix {expected!r}. Runner uploads to {expected} but the "
            f"ingest is reading from a different prefix — scan results will be "
            f"silently orphaned in MinIO."
        )


def test_jobs_next_response_contains_createdAt_field():
    """The runner observes job_pickup_latency_seconds (creation → claim) by
    reading job['createdAt'] in agent.py. The /jobs/next handler must return
    it or the metric stays at zero forever.
    """
    import inspect
    from src.runner.router import poll_next_job

    src = inspect.getsource(poll_next_job)
    assert '"createdAt"' in src, (
        "GET /api/v1/agent/jobs/next response does not include the 'createdAt' "
        "field. The runner uses it to observe pickup-latency metrics — without "
        "it, job_pickup_latency_seconds stays at zero forever."
    )


def test_backend_llm_env_keys_match_runner_read_keys():
    """The backend ships LLM_* config inside job['envVars']. The runner reads
    those keys via JobEnv. Asserts the key names line up so a typo on either
    side surfaces here instead of silently disabling agentic verification.
    """
    import inspect
    from src.settings.llm.service import build_llm_scan_env

    # Keys the backend writes into job['envVars'] for verification. Both scan
    # dispatch paths inject these via build_llm_scan_env, so assert against it.
    expected_keys = {
        "LLM_API_KEY",
        "LLM_API_BASE_URL",
        "LLM_API_MODEL",
        "LLM_TOKEN_BUDGET_PER_SCAN",
        "LLM_DAILY_REMAINING",
    }
    backend_src = inspect.getsource(build_llm_scan_env)
    for key in expected_keys:
        assert f'"{key}"' in backend_src, (
            f"backend dispatcher no longer emits the {key!r} env var. "
            f"If you renamed it, also update the runner reader in "
            f"runner/scanners/*/scanner.py::_build_llm_client / _build_scan_budget."
        )

    # Verify the runner reads at least the canonical LLM_API_KEY from JobEnv.
    # The other keys are scanner-specific (per-tool budget overrides etc.) and
    # follow the same path. Dependency + container scans no longer verify on the
    # runner (the backend matches SBOMs against the OSV mirror), and secrets rely
    # on TruffleHog verification rather than the LLM, so only the scanners that
    # still run agentic verification build an LLM client. All verifying scanners
    # share build_llm_client from runner.scanners._shared.
    from runner.scanners._shared import build_llm_client as shared_builder

    src = inspect.getsource(shared_builder)
    assert 'env.get("LLM_API_KEY")' in src, (
        "shared build_llm_client does not read LLM_API_KEY from JobEnv. "
        "The backend ships the key in job['envVars'], not in the process "
        "environment, so reading from os.environ here silently disables "
        "agentic verification for all scanners."
    )


def _capture_code_scanning_update(monkeypatch, *, preview):
    """Drive ingest_code_scanning_from_minio with zero findings and capture the
    run-status patch it writes, without touching the DB or object store."""
    from src.code_scanning import scanner as cs
    import src.shared.object_store as object_store
    import src.storage as storage
    import src.assets.service as assets_service

    captured: list[dict] = []
    # Empty (non-None) output means "scan ran, zero findings": proceeds to the
    # status transition we want to assert, while skipping lifecycle/notifications.
    monkeypatch.setattr(object_store, "find_findings_jsonl", lambda prefix: b"")
    monkeypatch.setattr(storage, "list_code_scanning_runs", lambda org: [])
    monkeypatch.setattr(cs, "update_code_scanning_run", lambda org, run_id, patch: captured.append(patch))
    monkeypatch.setattr(cs, "get_scan_sources_for_org", lambda org: [])
    monkeypatch.setattr(cs, "build_source_repo_list", lambda sources: [])
    monkeypatch.setattr(assets_service, "resolve_repo_asset_ids", lambda names: {})

    cs.ingest_code_scanning_from_minio("acme-org", "run-1", preview=preview)
    assert captured, "ingest wrote no run-status update"
    return captured[-1]


def test_code_scanning_preview_ingest_keeps_run_in_progress(monkeypatch):
    """A mid-scan preview ingest must never move the run to a terminal state;
    the verification tail is still running."""
    patch = _capture_code_scanning_update(monkeypatch, preview=True)
    assert patch["status"] != "completed"
    assert "finishedAt" not in patch
    assert patch.get("progress", {}).get("stage") != "completed"


def test_code_scanning_final_ingest_completes_run(monkeypatch):
    patch = _capture_code_scanning_update(monkeypatch, preview=False)
    assert patch["status"] == "completed"
    assert "finishedAt" in patch
    assert patch["progress"]["stage"] == "completed"


def _capture_iac_update(monkeypatch, *, preview):
    from src.iac import scanner as iac
    import src.shared.object_store as object_store
    import src.storage as storage

    captured: list[dict] = []
    monkeypatch.setattr(object_store, "find_findings_jsonl", lambda prefix: b"")
    monkeypatch.setattr(storage, "list_iac_runs", lambda org: [])
    monkeypatch.setattr(iac, "update_iac_run", lambda org, run_id, patch: captured.append(patch))

    iac.ingest_iac_from_minio("acme-org", "run-1", preview=preview)
    assert captured, "ingest wrote no run-status update"
    return captured[-1]


def test_iac_preview_ingest_keeps_run_in_progress(monkeypatch):
    patch = _capture_iac_update(monkeypatch, preview=True)
    assert patch["status"] != "completed"
    assert "finishedAt" not in patch
    assert patch.get("progress", {}).get("stage") != "completed"


def test_iac_final_ingest_completes_run(monkeypatch):
    patch = _capture_iac_update(monkeypatch, preview=False)
    assert patch["status"] == "completed"
    assert "finishedAt" in patch
    assert patch["progress"]["stage"] == "completed"
