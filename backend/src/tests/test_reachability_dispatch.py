"""Unit tests for the deps reachability enqueue helper.

The helper is gated on verification being enabled and only targets CVE-bearing
deps findings, grouped one job per asset. These tests stub ``create_job`` and
the enablement fetchers so no runner job or DB is touched.
"""
from __future__ import annotations

import json

from src.dependencies.reachability_dispatch import (
    REACHABILITY_JOB_TYPE,
    ReachabilityFinding,
    enqueue_reachability_jobs,
)
from src.settings.argus.service import ArgusConnectionDTO
from src.settings.llm.service import LlmConfigDTO


def _llm_enabled() -> LlmConfigDTO:
    return LlmConfigDTO(
        org_id="default",
        api_key="sk-test",
        api_base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
        scan_token_budget=100_000,
        daily_token_budget=1_000_000,
        enabled=True,
    )


def _argus_enabled() -> ArgusConnectionDTO:
    return ArgusConnectionDTO(
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="aegis-client",
        refresh_token="rt",
        enabled=True,
    )


def _install(monkeypatch, *, llm=None, argus=None, token="tok"):
    """Stub create_job + enablement fetchers; return the captured create_job kwargs.

    ``argus`` stands in for a fetched ArgusConnectionDTO — run_db (used only to
    load the Argus connection) is stubbed to return it directly, keeping the
    tests DB-free.
    """
    jobs: list[dict] = []
    monkeypatch.setattr(
        "src.runner.jobs.create_job",
        lambda **kw: jobs.append(kw) or {"id": f"job-{len(jobs)}"},
    )
    monkeypatch.setattr("src.shared.config.get_token_for_org", lambda org: token)
    monkeypatch.setattr("src.settings.llm.service.fetch_llm_config", lambda key: llm)
    monkeypatch.setattr("src.settings.llm.usage.daily_remaining", lambda **kw: 900_000)
    monkeypatch.setattr("src.db.helpers.run_db", lambda q: argus)
    # Deterministic clone-URL resolution independent of source-connection config.
    monkeypatch.setattr(
        "src.scans.service._resolve_repo_dispatch_target",
        lambda ref: (
            ref.split(":", 1)[0],
            ref.split(":", 1)[1].split("/", 1)[0],
            ref.split("/", 1)[-1],
            f"https://github.com/{ref.split(':', 1)[1]}.git",
        ),
    )
    return jobs


def _finding(**over) -> ReachabilityFinding:
    base = dict(
        finding_id="f1",
        asset_id="a1",
        external_ref="github:acme/api",
        package="requests",
        version="2.0.0",
        ecosystem="PyPI",
        cve="CVE-2024-0001",
    )
    base.update(over)
    return ReachabilityFinding(**base)


def test_llm_enabled_creates_reachability_job(monkeypatch):
    jobs = _install(monkeypatch, llm=_llm_enabled())

    ids = enqueue_reachability_jobs(org="acme", run_id="run-1", findings=[_finding()])

    assert len(ids) == 1
    assert len(jobs) == 1
    kw = jobs[0]
    assert kw["job_type"] == REACHABILITY_JOB_TYPE
    assert kw["org"] == "acme"
    assert kw["run_id"] == "run-1"

    env = kw["env_vars"]
    assert env["LLM_API_KEY"] == "sk-test"
    assert env["LLM_API_MODEL"] == "gpt-4o-mini"
    assert env["LLM_DAILY_REMAINING"] == "900000"
    assert "ARGUS_ENDPOINT" not in env
    assert env["GIT_REPOS"] == "https://github.com/acme/api.git"
    assert env["SOURCE_TYPE"] == "github"

    targets = json.loads(env["REACHABILITY_TARGETS"])
    assert targets == [
        {
            "finding_id": "f1",
            "package": "requests",
            "version": "2.0.0",
            "ecosystem": "PyPI",
            "cve": "CVE-2024-0001",
        }
    ]


def test_argus_only_enqueues_no_job(monkeypatch):
    # Reachability tracing is LLM-client-only (verify_deps_finding has no Argus
    # route), so a hosted-Argus-only org must NOT enqueue a job the runner can't
    # run — that would only strand a clone+job.
    jobs = _install(monkeypatch, llm=None, argus=_argus_enabled())

    ids = enqueue_reachability_jobs(org="acme", run_id="run-2", findings=[_finding()])

    assert ids == []
    assert jobs == []  # create_job never called


def test_verification_disabled_creates_no_job(monkeypatch):
    jobs = _install(monkeypatch, llm=None, argus=None)

    ids = enqueue_reachability_jobs(org="acme", run_id="run-3", findings=[_finding()])

    assert ids == []
    assert jobs == []


def test_no_cve_findings_creates_no_job(monkeypatch):
    jobs = _install(monkeypatch, llm=_llm_enabled())

    non_vuln = _finding(cve=None)
    ids = enqueue_reachability_jobs(org="acme", run_id="run-4", findings=[non_vuln])

    assert ids == []
    assert jobs == []


def test_multiple_assets_one_job_each(monkeypatch):
    jobs = _install(monkeypatch, llm=_llm_enabled())

    findings = [
        _finding(finding_id="f1", asset_id="a1", external_ref="github:acme/api",
                 package="requests", cve="CVE-2024-0001"),
        _finding(finding_id="f2", asset_id="a1", external_ref="github:acme/api",
                 package="flask", cve="CVE-2024-0002"),
        _finding(finding_id="f3", asset_id="a2", external_ref="github:acme/web",
                 package="lodash", ecosystem="npm", cve="CVE-2024-0003"),
    ]

    ids = enqueue_reachability_jobs(org="acme", run_id="run-5", findings=findings)

    assert len(ids) == 2
    assert len(jobs) == 2

    by_repo = {j["env_vars"]["GIT_REPOS"]: j for j in jobs}
    assert set(by_repo) == {
        "https://github.com/acme/api.git",
        "https://github.com/acme/web.git",
    }

    api_targets = json.loads(by_repo["https://github.com/acme/api.git"]["env_vars"]["REACHABILITY_TARGETS"])
    assert {t["finding_id"] for t in api_targets} == {"f1", "f2"}
    assert {t["package"] for t in api_targets} == {"requests", "flask"}

    web_targets = json.loads(by_repo["https://github.com/acme/web.git"]["env_vars"]["REACHABILITY_TARGETS"])
    assert [t["finding_id"] for t in web_targets] == ["f3"]
    assert web_targets[0]["ecosystem"] == "npm"
