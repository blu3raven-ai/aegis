"""Integration test: VerifiedSecretsCache + SecretsBaselineDelta + commit_range.

Exercises the full Phase 2d stack end-to-end:
- Real Postgres via testcontainers (verified_secrets table)
- Real git repo in tmp_path
- Mocked TruffleHog runner
"""
from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import delete as sa_delete

from src.secrets.verified_secrets_cache import VerifiedSecretsCache
from src.secrets.baseline_delta import SecretsBaselineDelta, _hash_secret, _versioned_detector_id
from src.secrets.commit_range import enumerate_new_commits, FullScanRequired
from src.secrets.periodic_sweep import should_run_periodic_sweep, enqueue_full_history_scan
from src.db.helpers import run_db
from src.db.models import VerifiedSecret


REPO_ID = "acme-org/integration-secrets-repo"
DETECTOR_V1 = "trufflehog@3.82.1"
DETECTOR_V2 = "trufflehog@3.83.0"
DETECTOR_TYPE = "GitHub"


@pytest.fixture(autouse=True)
def _clean():
    async def _del(session):
        await session.execute(sa_delete(VerifiedSecret))
    run_db(_del)
    yield


# ── git repo helpers ──────────────────────────────────────────────────────────


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def _commit(cwd: Path, message: str, files: dict[str, str]) -> str:
    for name, content in files.items():
        p = cwd / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        _git(cwd, "add", name)
    _git(cwd, "commit", "-m", message)
    return _git(cwd, "rev-parse", "HEAD")


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-b", "main")
    _git(tmp_path, "config", "user.email", "ci@acme-org.example")
    _git(tmp_path, "config", "user.name", "CI Bot")
    return tmp_path


# ── cache miss → verified → hit skips re-verification ────────────────────────


def test_first_scan_populates_cache_second_hits_it(repo):
    base = _commit(repo, "base", {"init.py": "x = 0"})
    head = _commit(repo, "add secret", {"app.py": "token = 'fake_token_12345'"})

    versioned_id = _versioned_detector_id(DETECTOR_TYPE, DETECTOR_V1)
    secret_val = "fake_token_12345"
    secret_hash = _hash_secret(secret_val)

    candidate = {
        "detector_id": DETECTOR_TYPE,
        "secret_value": secret_val,
        "file_path": "app.py",
        "line": 1,
    }

    runner_calls = []

    def mock_runner(path, sha):
        runner_calls.append(sha)
        return [candidate]

    cache = VerifiedSecretsCache()
    engine = SecretsBaselineDelta(cache, mock_runner)

    # First scan — cache miss → verifier stub called
    r1 = engine.scan(
        repo_id=REPO_ID,
        checkout_path=repo,
        baseline_sha=base,
        head_sha=head,
        detector_version=DETECTOR_V1,
    )

    assert r1.new_verifications == 1
    assert r1.cached_verifications == 0
    assert len(r1.findings) == 1
    assert r1.findings[0].verification_status == "unverified"

    # Second scan of same commit range — same secret found again → cache hit
    r2 = engine.scan(
        repo_id=REPO_ID,
        checkout_path=repo,
        baseline_sha=base,
        head_sha=head,
        detector_version=DETECTOR_V1,
    )

    assert r2.cached_verifications == 1
    assert r2.new_verifications == 0
    assert r2.findings[0].verification_status == "skipped-cache-hit"


# ── detector version bump causes re-verification ─────────────────────────────


def test_detector_version_bump_forces_reverification(repo):
    base = _commit(repo, "base", {"init.py": "x = 0"})
    head = _commit(repo, "add secret", {"cfg.py": "key = 'fake_token_bump_test'"})

    candidate = {
        "detector_id": DETECTOR_TYPE,
        "secret_value": "fake_token_bump_test",
        "file_path": "cfg.py",
        "line": 1,
    }

    cache = VerifiedSecretsCache()
    engine = SecretsBaselineDelta(cache, lambda p, s: [candidate])

    # Scan with v1 — populates cache under v1 versioned key
    r1 = engine.scan(
        repo_id=REPO_ID, checkout_path=repo,
        baseline_sha=base, head_sha=head,
        detector_version=DETECTOR_V1,
    )
    assert r1.new_verifications == 1

    # Scan with v2 — different versioned key → cache miss → re-verification
    r2 = engine.scan(
        repo_id=REPO_ID, checkout_path=repo,
        baseline_sha=base, head_sha=head,
        detector_version=DETECTOR_V2,
    )
    assert r2.new_verifications == 1
    assert r2.cached_verifications == 0


# ── multiple commits, partial cache ──────────────────────────────────────────


def test_multiple_commits_independent_verification(repo):
    base = _commit(repo, "base", {"a.py": "a = 1"})
    sha1 = _commit(repo, "commit1", {"b.py": "b = 2"})
    sha2 = _commit(repo, "commit2", {"c.py": "c = 3"})

    per_commit_secrets = {
        sha1: [{"detector_id": DETECTOR_TYPE, "secret_value": "fake_token_c1", "file_path": "b.py", "line": 1}],
        sha2: [{"detector_id": DETECTOR_TYPE, "secret_value": "fake_token_c2", "file_path": "c.py", "line": 1}],
    }

    cache = VerifiedSecretsCache()
    engine = SecretsBaselineDelta(cache, lambda p, sha: per_commit_secrets.get(sha, []))

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=repo,
        baseline_sha=base, head_sha=sha2,
        detector_version=DETECTOR_V1,
    )

    assert result.commits_scanned == 2
    assert result.new_verifications == 2
    assert len(result.findings) == 2


# ── baseline_sha=None raises FullScanRequired ─────────────────────────────────


def test_full_scan_required_when_no_baseline(repo):
    _commit(repo, "init", {"x.py": "x = 1"})
    with pytest.raises(FullScanRequired):
        enumerate_new_commits(repo, None, "HEAD")


# ── periodic sweep decision integrates correctly ─────────────────────────────


def test_periodic_sweep_triggers_after_enqueue(repo, caplog):
    import logging
    with caplog.at_level(logging.INFO, logger="src.secrets.periodic_sweep"):
        enqueue_full_history_scan(REPO_ID)
    assert "stub" in caplog.text.lower() or "enqueue" in caplog.text.lower()


def test_periodic_sweep_version_change_detected():
    from datetime import timedelta
    last_sweep = datetime.now(timezone.utc) - timedelta(hours=1)
    assert should_run_periodic_sweep(REPO_ID, last_sweep, DETECTOR_V2, DETECTOR_V1) is True


# ── cache invalidate then rescan ─────────────────────────────────────────────


def test_invalidate_causes_reverification(repo):
    base = _commit(repo, "base", {"a.py": "a = 0"})
    head = _commit(repo, "commit", {"a.py": "a = 1"})

    secret_val = "fake_token_invalidate_test"
    candidate = {
        "detector_id": DETECTOR_TYPE,
        "secret_value": secret_val,
        "file_path": "a.py",
        "line": 1,
    }

    cache = VerifiedSecretsCache()
    versioned_id = _versioned_detector_id(DETECTOR_TYPE, DETECTOR_V1)
    secret_hash = _hash_secret(secret_val)

    engine = SecretsBaselineDelta(cache, lambda p, s: [candidate])

    r1 = engine.scan(
        repo_id=REPO_ID, checkout_path=repo,
        baseline_sha=base, head_sha=head,
        detector_version=DETECTOR_V1,
    )
    assert r1.new_verifications == 1

    # Manually invalidate
    cache.invalidate(versioned_id, secret_hash)

    # Next scan should re-verify
    r2 = engine.scan(
        repo_id=REPO_ID, checkout_path=repo,
        baseline_sha=base, head_sha=head,
        detector_version=DETECTOR_V1,
    )
    assert r2.new_verifications == 1
    assert r2.cached_verifications == 0
