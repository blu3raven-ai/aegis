"""Manual /scans/manual repo dispatch must carry SOURCE_TYPE and a provider-
correct clone URL.

Without SOURCE_TYPE the runner callback can't resolve findings to assets; the
old code also hardcoded github.com, breaking GitLab/Bitbucket/Gitea repos.
"""
from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy import delete

from src.db.models import Asset, ScanRun


def _capture_dispatch(monkeypatch, *, argus=None):
    """Patch _dispatch_scanner_jobs' lazy imports; return list of created jobs.

    `argus` stands in for a fetched ArgusConnectionDTO — run_db (which the
    dispatch path uses only to load the Argus connection) is stubbed to return
    it directly, keeping these tests DB-free.
    """
    jobs: list[dict] = []
    monkeypatch.setattr("src.runner.jobs.create_job",
                        lambda **kw: jobs.append(kw) or {"id": kw.get("run_id")})
    monkeypatch.setattr("src.shared.config.get_token_for_org", lambda org: "tok")
    monkeypatch.setattr("src.settings.llm.service.fetch_llm_config", lambda key: None)
    monkeypatch.setattr("src.db.helpers.run_db", lambda q: argus)
    return jobs


def test_dispatch_sets_source_type_and_uses_provided_url(monkeypatch):
    from src.scans.service import _dispatch_scanner_jobs
    jobs = _capture_dispatch(monkeypatch)

    _dispatch_scanner_jobs(
        "scan-1", "acme/api", "c" * 40, ["dependencies_scanning", "code_scanning"], "acme",
        source_type="gitlab", repo_url="https://gl.acme.io/acme/api.git",
    )

    assert len(jobs) == 2
    for j in jobs:
        assert j["env_vars"]["SOURCE_TYPE"] == "gitlab"
        assert j["env_vars"]["GIT_REPOS"] == "https://gl.acme.io/acme/api.git"


def test_dispatch_ships_argus_env_when_enabled(monkeypatch):
    """An enabled Argus connection ships ARGUS_ENDPOINT + ARGUS_TOKEN to every job."""
    from src.scans.service import _dispatch_scanner_jobs
    from src.settings.argus.service import ArgusConnectionDTO

    conn = ArgusConnectionDTO(
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="aegis-client", refresh_token="rt", enabled=True,
    )
    # The dispatch mints a fresh short-lived access token; stub the exchange.
    monkeypatch.setattr(
        "src.settings.argus.service.mint_argus_access_token", lambda _conn: "minted-at-123"
    )
    jobs = _capture_dispatch(monkeypatch, argus=conn)

    _dispatch_scanner_jobs("scan-a", "acme/api", "c" * 40, ["dependencies_scanning"], "acme")

    env = jobs[0]["env_vars"]
    assert env["ARGUS_ENDPOINT"] == "https://argus.example.ai"
    assert env["ARGUS_TOKEN"] == "minted-at-123"


def test_dispatch_omits_argus_env_when_disabled(monkeypatch):
    """A disabled Argus connection ships no ARGUS_* env."""
    from src.scans.service import _dispatch_scanner_jobs
    from src.settings.argus.service import ArgusConnectionDTO

    conn = ArgusConnectionDTO(
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="aegis-client", refresh_token="rt", enabled=False,
    )
    jobs = _capture_dispatch(monkeypatch, argus=conn)

    _dispatch_scanner_jobs("scan-b", "acme/api", "c" * 40, ["dependencies_scanning"], "acme")

    env = jobs[0]["env_vars"]
    assert "ARGUS_ENDPOINT" not in env
    assert "ARGUS_TOKEN" not in env


def test_dispatch_falls_back_when_mint_fails(monkeypatch):
    """If the OAuth token mint fails, the scan ships no ARGUS_* (local fallback)."""
    from src.scans.service import _dispatch_scanner_jobs
    from src.settings.argus.service import ArgusAuthError, ArgusConnectionDTO

    conn = ArgusConnectionDTO(
        endpoint="https://argus.example.ai",
        token_endpoint="https://argus.example.ai/oauth/token",
        client_id="aegis-client", refresh_token="rt", enabled=True,
    )

    def _boom(_conn):
        raise ArgusAuthError("invalid_grant")

    monkeypatch.setattr("src.settings.argus.service.mint_argus_access_token", _boom)
    jobs = _capture_dispatch(monkeypatch, argus=conn)

    _dispatch_scanner_jobs("scan-d", "acme/api", "c" * 40, ["dependencies_scanning"], "acme")

    env = jobs[0]["env_vars"]
    assert "ARGUS_ENDPOINT" not in env
    assert "ARGUS_TOKEN" not in env


def test_dispatch_omits_argus_env_when_absent(monkeypatch):
    """No Argus connection configured -> no ARGUS_* env."""
    from src.scans.service import _dispatch_scanner_jobs
    jobs = _capture_dispatch(monkeypatch)

    _dispatch_scanner_jobs("scan-c", "acme/api", "c" * 40, ["dependencies_scanning"], "acme")

    env = jobs[0]["env_vars"]
    assert "ARGUS_ENDPOINT" not in env
    assert "ARGUS_TOKEN" not in env


def test_dispatch_legacy_fallback_no_source_type(monkeypatch):
    """CI caller passes neither source_type nor repo_url — behaviour unchanged."""
    from src.scans.service import _dispatch_scanner_jobs
    jobs = _capture_dispatch(monkeypatch)

    _dispatch_scanner_jobs("scan-2", "acme/api", "c" * 40, ["dependencies_scanning"], "acme")

    env = jobs[0]["env_vars"]
    assert env["GIT_REPOS"] == "https://github.com/acme/api"
    assert "SOURCE_TYPE" not in env


@pytest.mark.asyncio
async def test_submit_repo_scan_resolves_provider_url_and_source_type(db_session, monkeypatch):
    """End-to-end through submit_scan: a gitlab asset dispatches gitlab-clone-URL
    jobs stamped SOURCE_TYPE=gitlab — never github."""
    from src.scans.service import submit_scan

    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="source_connection",
        external_ref=f"gitlab:acme/api-{asset_id[:8]}",
        display_name="acme/api", asset_metadata={},
    ))
    await db_session.commit()

    @asynccontextmanager
    async def _patched_get_session():
        yield db_session

    jobs = _capture_dispatch(monkeypatch)
    monkeypatch.setattr("src.scans.service.get_session", _patched_get_session)
    # No source connections seeded -> instance_url resolves to "" (SaaS default).
    monkeypatch.setattr("src.shared.config.get_instance_url_for_org", lambda org, st: "")

    try:
        sub = await submit_scan(asset_id, "user-1", commit_sha="a" * 40,
                                scanner_types=["dependencies_scanning"])
        assert sub is not None
        env = jobs[0]["env_vars"]
        assert env["SOURCE_TYPE"] == "gitlab"
        assert env["GIT_REPOS"].startswith("https://gitlab.com/acme/api-")
        assert env["GIT_REPOS"].endswith(".git")
    finally:
        await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()


@pytest.mark.asyncio
async def test_submit_ci_scan_resolves_provider_url_and_source_type(db_session, monkeypatch):
    """CI dispatch resolves SOURCE_TYPE + a provider clone URL from the asset's
    external_ref — never the bare github.com/{uuid} the UUID source_id implied."""
    from src.scans.service import submit_ci_scan

    asset_id = str(uuid.uuid4())
    db_session.add(Asset(
        id=asset_id, type="repo", source="byo_import",
        external_ref=f"gitlab:acme/api-{asset_id[:8]}",
        display_name="acme/api", asset_metadata={},
    ))
    await db_session.commit()

    @asynccontextmanager
    async def _patched_get_session():
        yield db_session

    jobs = _capture_dispatch(monkeypatch)
    monkeypatch.setattr("src.scans.service.get_session", _patched_get_session)
    monkeypatch.setattr("src.shared.config.get_instance_url_for_org", lambda org, st: "")

    try:
        sub = await submit_ci_scan(
            org="", source_id=asset_id, commit_sha="a" * 40,
            branch="main", pr_number=None, api_key_id=1,
        )
        assert sub.repo_id == asset_id  # submission still keyed by asset id
        for env in (j["env_vars"] for j in jobs):
            assert env["SOURCE_TYPE"] == "gitlab"
            assert env["GIT_REPOS"].startswith("https://gitlab.com/acme/api-")
            assert env["GIT_REPOS"].endswith(".git")
    finally:
        await db_session.execute(delete(ScanRun).where(ScanRun.asset_id == asset_id))
        await db_session.execute(delete(Asset).where(Asset.id == asset_id))
        await db_session.commit()
