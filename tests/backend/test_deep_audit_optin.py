"""deep_audit is a selectable code-repo scanner but opt-in: it must never run on
the default "scan everything" path, only when explicitly selected."""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.sources import triggers  # noqa: E402
from src.deep_audit.lifecycle import deep_audit_identity  # noqa: E402


def _patch_dispatch_sinks(monkeypatch):
    import src.runner.jobs as jobs
    import src.storage as storage

    monkeypatch.setattr(jobs, "create_job", lambda **kwargs: None)
    for name in (
        "create_dependencies_run",
        "create_code_scanning_run",
        "create_container_scanning_run",
        "create_secret_run",
        "create_iac_run",
        "create_agent_run",
        "create_deep_audit_run",
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
    return {rid.rsplit("-", 1)[1] for rid in run_ids}


def test_deep_audit_selectable_for_code_repositories():
    assert "deep_audit" in triggers.SCANNERS_BY_CATEGORY["code-repositories"]


def test_deep_audit_excluded_from_default_scan(monkeypatch):
    """Empty selection = scan-everything; deep_audit must NOT be dispatched."""
    _patch_dispatch_sinks(monkeypatch)
    queued = triggers.dispatch_source_scan(_code_connection([]), run_prefix="manual")
    assert "deep_audit" not in _scanner_types(queued)


def test_deep_audit_runs_when_explicitly_selected(monkeypatch):
    _patch_dispatch_sinks(monkeypatch)
    queued = triggers.dispatch_source_scan(
        _code_connection(["deep_audit"]), run_prefix="manual"
    )
    assert _scanner_types(queued) == {"deep_audit"}


def test_identity_key_includes_resource():
    """The resource (endpoint) disambiguates multiple findings in one router file."""
    a = deep_audit_identity("acme-org/api", "app/router.py", "BOLA-001", "POST /users/{id}")
    b = deep_audit_identity("acme-org/api", "app/router.py", "BOLA-001", "GET /users/{id}")
    assert a != b
    # Line-independent: same identity regardless of surrounding edits.
    assert a == deep_audit_identity("acme-org/api", "app/router.py", "BOLA-001", "POST /users/{id}")
