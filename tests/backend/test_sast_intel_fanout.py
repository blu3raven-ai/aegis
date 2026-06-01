"""Tests for dispatch_rule_pack_update_fanout and _enqueue_full_rescan."""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
from sqlalchemy import delete as sa_delete

from src.code_scanning.intel_fanout import (
    _enqueue_full_rescan,
    dispatch_rule_pack_update_fanout,
)
from src.code_scanning.file_finding_cache import FileFindingCache, Finding, _CACHE_TYPE
from src.db.helpers import run_db
from src.db.models import CacheEntry
from src.shared.config import ScanSource


REPO_A = "acme-org/fanout-repo-a"
REPO_B = "acme-org/fanout-repo-b"
SHA_A = "a" * 64
SHA_B = "b" * 64
FILE = "src/app.py"
RULE_PACK_V1 = "rules-v1.0.0"
RULE_PACK_V2 = "rules-v2.0.0"

SAMPLE_FINDING = Finding(
    file_path=FILE, line=1, rule_id="xss", severity="medium", message="XSS"
)

_FAKE_SOURCE = ScanSource(
    connection_id="conn-1",
    category="code-repositories",
    source_type="github",
    org="acme-org",
    token="gh-token-secret",
    repo_urls=["https://github.com/acme-org/fanout-repo-a.git"],
    container_images=[],
    registry_token="",
    registry_username="",
)

_FAKE_SCANNER_CONFIG = {
    "image": "aegis/scanner-code-scanning:latest",
    "concurrency": "4",
    "rulesets": "p/owasp-top-ten,p/cwe-top-25",
    "aiAutoClassifyOnScan": "false",
    "aiReviewEnabled": "false",
    "aiApiKey": "",
    "aiBaseUrl": "https://api.openai.com/v1",
    "aiModelName": "gpt-4o-mini",
}


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(
            sa_delete(CacheEntry).where(
                CacheEntry.cache_type == _CACHE_TYPE,
                CacheEntry.cache_key.like("acme-org/%"),
            )
        )
    run_db(_del)
    yield


# ── basic dispatch ───────────────────────────────────────────────────────────


def test_fanout_empty_cache_returns_zero():
    cache = FileFindingCache()
    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 0


def test_fanout_up_to_date_repo_not_enqueued():
    """A repo whose all entries already use the new rule pack must not be enqueued."""
    cache = FileFindingCache()
    cache.put(REPO_A, FILE, SHA_A, [SAMPLE_FINDING], RULE_PACK_V2)

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 0


def test_fanout_stale_repo_is_enqueued():
    """A repo with cached entries from an older rule pack must be enqueued."""
    cache = FileFindingCache()
    cache.put(REPO_A, FILE, SHA_A, [SAMPLE_FINDING], RULE_PACK_V1)

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 1


def test_fanout_counts_only_stale_repos():
    """Only repos with stale rule packs are counted."""
    cache = FileFindingCache()
    cache.put(REPO_A, FILE, SHA_A, [SAMPLE_FINDING], RULE_PACK_V1)  # stale
    cache.put(REPO_B, FILE, SHA_B, [SAMPLE_FINDING], RULE_PACK_V2)  # current

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 1


def test_fanout_multiple_stale_repos():
    cache = FileFindingCache()
    cache.put(REPO_A, FILE, SHA_A, [SAMPLE_FINDING], RULE_PACK_V1)
    cache.put(REPO_B, FILE, SHA_B, [SAMPLE_FINDING], RULE_PACK_V1)

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 2


def test_fanout_repo_with_mixed_entries_is_stale():
    """A repo with some entries on old and some on new rule pack is still stale."""
    cache = FileFindingCache()
    cache.put(REPO_A, "src/a.py", SHA_A, [SAMPLE_FINDING], RULE_PACK_V1)
    cache.put(REPO_A, "src/b.py", SHA_B, [SAMPLE_FINDING], RULE_PACK_V2)

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)
    assert count == 1


def test_fanout_returns_int():
    cache = FileFindingCache()
    result = dispatch_rule_pack_update_fanout(RULE_PACK_V1, cache)
    assert isinstance(result, int)


# ── _enqueue_full_rescan — job dispatch ─────────────────────────────────────


def test_enqueue_dispatches_create_job(monkeypatch):
    """A repo with a connected source must result in a create_job call."""
    mock_create_job = MagicMock(return_value={"id": "job-abc"})
    monkeypatch.setattr("src.code_scanning.intel_fanout.secrets.token_hex", lambda n: "deadbeef")

    with (
        patch("src.shared.config.get_scan_sources_for_org", return_value=[_FAKE_SOURCE]),
        patch("src.shared.config.get_code_scanning_scanner_config", return_value=_FAKE_SCANNER_CONFIG),
        patch("src.runner.jobs.create_job", mock_create_job),
    ):
        _enqueue_full_rescan(REPO_A, RULE_PACK_V2)

    mock_create_job.assert_called_once()
    kwargs = mock_create_job.call_args
    assert kwargs.kwargs["job_type"] == "code_scanning"
    assert kwargs.kwargs["org"] == "acme-org"
    assert kwargs.kwargs["run_id"] == "deadbeef"
    assert kwargs.kwargs["env_vars"]["GIT_REPOS"] == "https://github.com/acme-org/fanout-repo-a.git"
    assert kwargs.kwargs["env_vars"]["ORG_LABEL"] == "acme-org"
    # Token must never be logged — only check it's present, not its value
    assert "GIT_TOKEN" in kwargs.kwargs["env_vars"]
    assert kwargs.kwargs["expected_repo_count"] == 1


def test_enqueue_uses_scanner_config_image_and_rulesets(monkeypatch):
    """Docker image and rulesets come from get_code_scanning_scanner_config."""
    mock_create_job = MagicMock(return_value={"id": "job-xyz"})
    custom_config = {**_FAKE_SCANNER_CONFIG, "image": "custom/scanner:v2", "rulesets": "p/custom"}

    with (
        patch("src.shared.config.get_scan_sources_for_org", return_value=[_FAKE_SOURCE]),
        patch("src.shared.config.get_code_scanning_scanner_config", return_value=custom_config),
        patch("src.runner.jobs.create_job", mock_create_job),
    ):
        _enqueue_full_rescan(REPO_A, RULE_PACK_V2)

    kwargs = mock_create_job.call_args.kwargs
    assert kwargs["docker_image"] == "custom/scanner:v2"
    assert kwargs["env_vars"]["RULESETS"] == "p/custom"


def test_enqueue_no_source_skips_without_raising(monkeypatch):
    """Missing source connection must log a warning and not raise."""
    mock_create_job = MagicMock()

    with (
        patch("src.shared.config.get_scan_sources_for_org", return_value=[]),
        patch("src.runner.jobs.create_job", mock_create_job),
    ):
        _enqueue_full_rescan(REPO_A, RULE_PACK_V2)  # must not raise

    mock_create_job.assert_not_called()


def test_enqueue_no_token_skips_without_raising(monkeypatch):
    """A source with an empty token must not dispatch a job."""
    mock_create_job = MagicMock()
    tokenless = ScanSource(
        connection_id="conn-2",
        category="code-repositories",
        source_type="github",
        org="acme-org",
        token="",
        repo_urls=["https://github.com/acme-org/fanout-repo-a.git"],
        container_images=[],
        registry_token="",
        registry_username="",
    )

    with (
        patch("src.shared.config.get_scan_sources_for_org", return_value=[tokenless]),
        patch("src.runner.jobs.create_job", mock_create_job),
    ):
        _enqueue_full_rescan(REPO_A, RULE_PACK_V2)

    mock_create_job.assert_not_called()


def test_enqueue_malformed_repo_id_skips_without_raising():
    """A repo_id without a '/' must log a warning and not raise."""
    mock_create_job = MagicMock()

    with patch("src.runner.jobs.create_job", mock_create_job):
        _enqueue_full_rescan("no-slash-here", RULE_PACK_V2)

    mock_create_job.assert_not_called()


def test_enqueue_combines_urls_from_multiple_sources(monkeypatch):
    """All repo URLs across multiple sources for the same org are passed to the job."""
    mock_create_job = MagicMock(return_value={"id": "job-multi"})
    source_b = ScanSource(
        connection_id="conn-3",
        category="code-repositories",
        source_type="github",
        org="acme-org",
        token="gh-token-2",
        repo_urls=["https://github.com/acme-org/fanout-repo-b.git"],
        container_images=[],
        registry_token="",
        registry_username="",
    )

    with (
        patch("src.shared.config.get_scan_sources_for_org", return_value=[_FAKE_SOURCE, source_b]),
        patch("src.shared.config.get_code_scanning_scanner_config", return_value=_FAKE_SCANNER_CONFIG),
        patch("src.runner.jobs.create_job", mock_create_job),
    ):
        _enqueue_full_rescan(REPO_A, RULE_PACK_V2)

    kwargs = mock_create_job.call_args.kwargs
    repo_list = kwargs["env_vars"]["GIT_REPOS"].split(",")
    assert len(repo_list) == 2
    assert kwargs["expected_repo_count"] == 2


def test_fanout_dispatches_job_per_stale_repo(monkeypatch):
    """dispatch_rule_pack_update_fanout must call _enqueue_full_rescan once per stale repo."""
    cache = FileFindingCache()
    cache.put(REPO_A, FILE, SHA_A, [SAMPLE_FINDING], RULE_PACK_V1)
    cache.put(REPO_B, FILE, SHA_B, [SAMPLE_FINDING], RULE_PACK_V1)

    enqueue_calls: list[str] = []

    def fake_enqueue(repo_id: str, rule_pack_version: str) -> None:
        enqueue_calls.append(repo_id)

    monkeypatch.setattr("src.code_scanning.intel_fanout._enqueue_full_rescan", fake_enqueue)

    count = dispatch_rule_pack_update_fanout(RULE_PACK_V2, cache)

    assert count == 2
    assert set(enqueue_calls) == {REPO_A, REPO_B}
