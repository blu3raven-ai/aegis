"""Per-source scanner selection: validation + dispatch intersection."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

import pytest  # noqa: E402

from src.sources import store as sources_store  # noqa: E402
from src.sources.store import SourceValidationError  # noqa: E402
from src.sources import triggers  # noqa: E402


# ── _validate_scanners ────────────────────────────────────────────────────────

def test_validate_scanners_accepts_applicable_subset():
    sources_store._validate_scanners(
        "code-repositories", ["secret_scanning", "code_scanning"]
    )


def test_validate_scanners_accepts_empty_meaning_all():
    sources_store._validate_scanners("code-repositories", [])


def test_validate_scanners_rejects_inapplicable_scanner():
    with pytest.raises(SourceValidationError):
        # container_scanning is not valid for code repositories.
        sources_store._validate_scanners("code-repositories", ["container_scanning"])


def test_validate_scanners_rejects_non_list():
    with pytest.raises(SourceValidationError):
        sources_store._validate_scanners("code-repositories", "secret_scanning")


# ── dispatch intersection ─────────────────────────────────────────────────────

def _patch_dispatch_sinks(monkeypatch):
    """Stub the job queue + run-record creators so dispatch runs without I/O."""
    import src.runner.jobs as jobs
    import src.storage as storage

    monkeypatch.setattr(jobs, "create_job", lambda **kwargs: None)
    for name in (
        "create_dependencies_run",
        "create_code_scanning_run",
        "create_container_scanning_run",
        "create_secret_run",
        "create_iac_run",
    ):
        monkeypatch.setattr(storage, name, lambda org, run_id: None)


def _code_connection(scanners):
    return {
        "auth": {"orgOrOwner": "acme-org", "token": "t"},
        "sourceType": "github",
        "category": "code-repositories",
        "discoveredItems": ["acme-org/api"],
        "scanners": scanners,
    }


def _scanner_types(run_ids):
    # run_id format: "{prefix}-{ts}-{scanner_type}"
    return {rid.split("-", 2)[2] for rid in run_ids}


def test_dispatch_empty_selection_runs_all_applicable(monkeypatch):
    _patch_dispatch_sinks(monkeypatch)
    queued = triggers.dispatch_source_scan(_code_connection([]), run_prefix="manual")
    assert _scanner_types(queued) == {
        "dependencies_scanning",
        "secret_scanning",
        "code_scanning",
        "iac_scanning",
        "agent_scanning",
    }


def test_dispatch_honours_subset_selection(monkeypatch):
    _patch_dispatch_sinks(monkeypatch)
    queued = triggers.dispatch_source_scan(
        _code_connection(["secret_scanning"]), run_prefix="manual"
    )
    assert _scanner_types(queued) == {"secret_scanning"}


def test_dispatch_preserves_canonical_scanner_order(monkeypatch):
    _patch_dispatch_sinks(monkeypatch)
    # Selection given out of order; dispatch must follow SCANNERS_BY_CATEGORY order.
    queued = triggers.dispatch_source_scan(
        _code_connection(["code_scanning", "dependencies_scanning"]),
        run_prefix="manual",
    )
    ordered = [rid.split("-", 2)[2] for rid in queued]
    assert ordered == ["dependencies_scanning", "code_scanning"]
