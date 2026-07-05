"""Unit tests for secrets/periodic_sweep.py.

Tests run without a real database or runner — all external dependencies are
mocked so no Postgres, MinIO, or runner infrastructure is needed.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch


os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("APP_SECRET", "0" * 64)

from src.secrets.periodic_sweep import (  # noqa: E402
    should_run_periodic_sweep,
    enqueue_full_history_scan,
    _DEFAULT_SWEEP_DAYS,
)


# ── should_run_periodic_sweep ─────────────────────────────────────────────────

def test_force_sweep_always_true():
    now = datetime.now(timezone.utc)
    assert should_run_periodic_sweep("acme-org/0", now, "v1", "v1", force_sweep=True) is True


def test_never_swept_returns_true():
    assert should_run_periodic_sweep("acme-org/0", None, "v1", None) is True


def test_detector_version_changed_returns_true():
    recent = datetime.now(timezone.utc) - timedelta(days=1)
    assert should_run_periodic_sweep("acme-org/0", recent, "v2", "v1") is True


def test_within_window_same_version_returns_false():
    recent = datetime.now(timezone.utc) - timedelta(days=1)
    assert should_run_periodic_sweep("acme-org/0", recent, "v1", "v1") is False


def test_expired_window_returns_true():
    stale = datetime.now(timezone.utc) - timedelta(days=_DEFAULT_SWEEP_DAYS + 1)
    assert should_run_periodic_sweep("acme-org/0", stale, "v1", "v1") is True


def test_boundary_just_within_window_returns_false():
    # One second inside the cutoff — should not trigger.
    just_fresh = datetime.now(timezone.utc) - timedelta(days=_DEFAULT_SWEEP_DAYS) + timedelta(seconds=5)
    assert should_run_periodic_sweep("acme-org/0", just_fresh, "v1", "v1") is False


# ── enqueue_full_history_scan ─────────────────────────────────────────────────

def _make_source(org: str, repo_urls: list[str], token: str = "tok-123") -> MagicMock:
    source = MagicMock()
    source.org = org
    source.token = token
    source.repo_urls = repo_urls
    return source


def test_enqueue_dispatches_one_job_per_source():
    """One runner job is created for each source that has repos."""
    sources = [
        _make_source("acme-org", ["https://github.com/acme-org/alpha.git"]),
        _make_source("acme-org", ["https://github.com/acme-org/beta.git",
                                   "https://github.com/acme-org/gamma.git"]),
    ]
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "", "scanDepth": "light"}

    with patch("src.secrets.periodic_sweep.create_job") as mock_create, \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=sources), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        # Inline imports happen inside the function; patch the names it resolves
        enqueue_full_history_scan("acme-org/0")

    assert mock_create.call_count == 2


def test_enqueue_omits_start_date_for_full_history():
    """A full sweep omits SCAN_START_DATE so the runner scans the entire git
    history (secret scans always run full git history)."""
    source = _make_source("acme-org", ["https://github.com/acme-org/repo.git"])
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "2024-01-01"}

    captured_env: dict = {}

    def _capture_create(**kwargs):
        captured_env.update(kwargs.get("env_vars", {}))
        return {"id": "job-abc"}

    with patch("src.secrets.periodic_sweep.create_job", side_effect=_capture_create), \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[source]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        enqueue_full_history_scan("acme-org/0")

    # SCAN_START_DATE must not be set for a full history sweep
    assert "SCAN_START_DATE" not in captured_env


def test_enqueue_sets_expected_repo_count():
    """expected_repo_count matches the number of repo URLs in the source."""
    repos = [
        "https://github.com/acme-org/a.git",
        "https://github.com/acme-org/b.git",
        "https://github.com/acme-org/c.git",
    ]
    source = _make_source("acme-org", repos)
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "", "scanDepth": "light"}

    captured_kwargs: dict = {}

    def _capture(**kwargs):
        captured_kwargs.update(kwargs)
        return {"id": "job-abc"}

    with patch("src.secrets.periodic_sweep.create_job", side_effect=_capture), \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[source]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        enqueue_full_history_scan("acme-org/0")

    assert captured_kwargs.get("expected_repo_count") == 3


def test_enqueue_no_sources_returns_early():
    """When no code-repository sources exist, no job is dispatched."""
    with patch("src.secrets.periodic_sweep.create_job") as mock_create, \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config",
               return_value={"image": "aegis/scanner-secrets:latest", "concurrency": "4",
                             "scanStartDate": "", "scanDepth": "light"}):
        enqueue_full_history_scan("acme-org/0")

    mock_create.assert_not_called()


def test_enqueue_invalid_repo_id_no_slash():
    """repo_id without a slash is rejected without calling any external dependency."""
    with patch("src.secrets.periodic_sweep.get_scan_sources_for_org") as mock_sources, \
         patch("src.secrets.periodic_sweep.create_job") as mock_create:
        enqueue_full_history_scan("no-slash-here")

    mock_sources.assert_not_called()
    mock_create.assert_not_called()


def test_enqueue_empty_repo_id():
    """Empty repo_id is rejected without calling any external dependency."""
    with patch("src.secrets.periodic_sweep.get_scan_sources_for_org") as mock_sources, \
         patch("src.secrets.periodic_sweep.create_job") as mock_create:
        enqueue_full_history_scan("")

    mock_sources.assert_not_called()
    mock_create.assert_not_called()


def test_enqueue_skips_sources_without_repos():
    """Sources with empty repo_urls are skipped; only sources with repos get a job."""
    sources = [
        _make_source("acme-org", []),  # no repos — should be skipped
        _make_source("acme-org", ["https://github.com/acme-org/main.git"]),
    ]
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "", "scanDepth": "light"}

    with patch("src.secrets.periodic_sweep.create_job") as mock_create, \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=sources), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        enqueue_full_history_scan("acme-org/0")

    assert mock_create.call_count == 1


def test_enqueue_job_type_is_secrets():
    """The dispatched job must be of the secret-scanning job type."""
    source = _make_source("acme-org", ["https://github.com/acme-org/repo.git"])
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "", "scanDepth": "light"}

    with patch("src.secrets.periodic_sweep.create_job") as mock_create, \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[source]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        mock_create.return_value = {"id": "job-xyz"}
        enqueue_full_history_scan("acme-org/0")

    _, kwargs = mock_create.call_args
    assert kwargs.get("job_type") == "secret_scanning"


def test_enqueue_org_label_set_correctly():
    """ORG_LABEL in env_vars matches the org extracted from repo_id."""
    source = _make_source("example-org", ["https://github.com/example-org/repo.git"])
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "2",
              "scanStartDate": "", "scanDepth": "light"}

    captured_env: dict = {}

    def _capture(**kwargs):
        captured_env.update(kwargs.get("env_vars", {}))
        return {"id": "job-abc"}

    with patch("src.secrets.periodic_sweep.create_job", side_effect=_capture), \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[source]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config):
        enqueue_full_history_scan("example-org/2")

    assert captured_env.get("ORG_LABEL") == "example-org"


def test_enqueue_token_not_logged(caplog):
    """The GIT_TOKEN value must not appear in any log output."""
    import logging
    secret_token = "super-secret-token-xyz"
    source = _make_source("acme-org", ["https://github.com/acme-org/repo.git"], token=secret_token)
    config = {"image": "aegis/scanner-secrets:latest", "concurrency": "4",
              "scanStartDate": "", "scanDepth": "light"}

    with patch("src.secrets.periodic_sweep.create_job", return_value={"id": "job-1"}), \
         patch("src.secrets.periodic_sweep.get_scan_sources_for_org", return_value=[source]), \
         patch("src.secrets.periodic_sweep.get_secret_scanner_config", return_value=config), \
         caplog.at_level(logging.DEBUG, logger="src.secrets.periodic_sweep"):
        enqueue_full_history_scan("acme-org/0")

    for record in caplog.records:
        assert secret_token not in record.getMessage(), (
            f"Token leaked into log message: {record.getMessage()!r}"
        )
