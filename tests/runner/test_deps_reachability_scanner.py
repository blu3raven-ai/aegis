"""Tests for the dependency reachability scanner (job handler)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from runner.scanners.deps_reachability.scanner import DepsReachabilityScanner


def _job(**env) -> dict:
    return {"jobId": "reach-1", "type": "dependencies_reachability", "envVars": env}


def _targets(*targets: dict) -> str:
    return json.dumps(list(targets))


def _reachable_llm() -> MagicMock:
    llm = MagicMock()
    llm._model = "stub"
    llm.chat.return_value = MagicMock(
        content=(
            '{"reachability":"reachable","evidence":'
            '[{"kind":"sink","file":"main.py","line":2,"snippet":"evilpkg.vuln_fn()"}]}'
        ),
        tokens_in=1,
        tokens_out=1,
        prompt_hash="h",
    )
    return llm


def _patch_clone(monkeypatch, *, source: str) -> None:
    """Replace the real git clone with one that materialises a fixed source file."""
    def fake_clone(url, dest, **kwargs):
        d = Path(dest)
        d.mkdir(parents=True, exist_ok=True)
        (d / "main.py").write_text(source)

    monkeypatch.setattr(
        "runner.scanners.deps_reachability.scanner.clone_repo", fake_clone
    )


def test_dispatcher_registers_reachability_type():
    from runner.core.dispatcher import get_scanner, supported_types

    assert "dependencies_reachability" in supported_types()
    assert isinstance(get_scanner("dependencies_reachability"), DepsReachabilityScanner)


def test_reachable_target_written_per_finding_id(tmp_path, monkeypatch):
    _patch_clone(monkeypatch, source="import evilpkg\nevilpkg.vuln_fn()\n")
    monkeypatch.setattr(
        "runner.scanners.deps_reachability.scanner.build_llm_client",
        lambda env: _reachable_llm(),
    )
    register_calls: list = []
    monkeypatch.setattr(
        "runner.scanners.deps_reachability.scanner.register_output",
        lambda out_dir, path, repo: register_calls.append((path.name, repo)),
    )

    job = _job(
        GIT_REPOS="https://example.com/acme-org/widget.git",
        GIT_TOKEN="tok",
        RUN_ID="run-42",
        REACHABILITY_TARGETS=_targets(
            {
                "finding_id": "f-1",
                "package": "evilpkg",
                "version": "1.0.0",
                "ecosystem": "pypi",
                "cve": "CVE-1",
            }
        ),
    )

    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 0

    payload = json.loads(next(tmp_path.rglob("reachability-results.json")).read_text())
    assert payload["run_id"] == "run-42"
    by_id = {r["finding_id"]: r for r in payload["results"]}
    assert by_id["f-1"]["reachability"] == "reachable"
    assert by_id["f-1"]["evidence"]
    assert register_calls and register_calls[0][0] == "reachability-results.json"


def test_pre_filter_marks_unimported_package_no_path(tmp_path, monkeypatch):
    """A package that is never imported short-circuits to no_path (no LLM spend)."""
    _patch_clone(monkeypatch, source="import os\n")
    llm = _reachable_llm()
    monkeypatch.setattr(
        "runner.scanners.deps_reachability.scanner.build_llm_client",
        lambda env: llm,
    )

    job = _job(
        GIT_REPOS="https://example.com/acme-org/widget.git",
        RUN_ID="run-7",
        REACHABILITY_TARGETS=_targets(
            {"finding_id": "f-9", "package": "ghostpkg", "version": "2.0", "ecosystem": "pypi"}
        ),
    )

    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 0
    payload = json.loads(next(tmp_path.rglob("reachability-results.json")).read_text())
    assert payload["results"][0]["reachability"] == "no_path"
    llm.chat.assert_not_called()


def test_no_llm_key_writes_empty_results_and_succeeds(tmp_path, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    called = {"cloned": False}

    def fake_clone(url, dest, **kwargs):
        called["cloned"] = True

    monkeypatch.setattr(
        "runner.scanners.deps_reachability.scanner.clone_repo", fake_clone
    )

    job = _job(
        GIT_REPOS="https://example.com/acme-org/widget.git",
        RUN_ID="run-empty",
        REACHABILITY_TARGETS=_targets(
            {"finding_id": "f-1", "package": "evilpkg", "version": "1.0.0", "ecosystem": "pypi"}
        ),
    )

    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 0
    payload = json.loads(next(tmp_path.rglob("reachability-results.json")).read_text())
    assert payload == {"run_id": "run-empty", "results": []}
    # No key -> no clone, no crash.
    assert called["cloned"] is False


def test_missing_targets_returns_graceful_error(tmp_path):
    job = _job(GIT_REPOS="https://example.com/acme-org/widget.git", RUN_ID="run-x")
    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 2
    assert not list(tmp_path.rglob("reachability-results.json"))


def test_invalid_targets_json_returns_graceful_error(tmp_path):
    job = _job(
        GIT_REPOS="https://example.com/acme-org/widget.git",
        RUN_ID="run-x",
        REACHABILITY_TARGETS="{not json",
    )
    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 2
    assert not list(tmp_path.rglob("reachability-results.json"))


def test_missing_repos_returns_graceful_error(tmp_path):
    job = _job(
        RUN_ID="run-x",
        REACHABILITY_TARGETS=_targets(
            {"finding_id": "f-1", "package": "evilpkg", "version": "1.0.0", "ecosystem": "pypi"}
        ),
    )
    result = DepsReachabilityScanner().run_scan(job, tmp_path)
    assert result.exit_code == 2
