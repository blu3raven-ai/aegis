"""Tests for SecretsBaselineDelta — cache-aware secrets scan engine."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

from src.secrets.baseline_delta import (
    SecretsBaselineDelta,
    SecretFinding,
    SecretsScanResult,
    _hash_secret,
    _versioned_detector_id,
)
from src.secrets.verified_secrets_cache import VerifiedSecretsCache


REPO_ID = "acme-org/delta-secrets-repo"
DETECTOR_V1 = "trufflehog@3.82.1"
DETECTOR_V2 = "trufflehog@3.83.0"
DETECTOR_TYPE = "AWS"


# ── test helpers ──────────────────────────────────────────────────────────────


def _make_commit(sha: str, files=None):
    from src.secrets.commit_range import CommitInfo
    from datetime import datetime, timezone
    return CommitInfo(
        sha=sha,
        author_email="dev@acme-org.example",
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        message="test commit",
        changed_files=files or ["app.py"],
    )


def _candidate(secret_value: str, file_path: str = "app.py", line: int = 10) -> dict:
    return {
        "detector_id": DETECTOR_TYPE,
        "secret_value": secret_value,
        "file_path": file_path,
        "line": line,
    }


# ── cache hit path ────────────────────────────────────────────────────────────


def test_cache_hit_skips_verification(monkeypatch):
    """When cache has a valid entry for a secret, verifier is not called."""
    secret_val = "fake_token_12345"
    secret_hash = _hash_secret(secret_val)
    versioned_id = _versioned_detector_id(DETECTOR_TYPE, DETECTOR_V1)

    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    from src.secrets.verified_secrets_cache import VerificationStatus
    from datetime import datetime, timezone, timedelta
    mock_cache.get.return_value = VerificationStatus(
        status="verified",
        verified_at=datetime.now(timezone.utc),
        ttl_until=datetime.now(timezone.utc) + timedelta(days=7),
    )

    commits = [_make_commit("abc123")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )

    mock_runner = MagicMock(return_value=[_candidate(secret_val)])
    engine = SecretsBaselineDelta(mock_cache, mock_runner)

    result = engine.scan(
        repo_id=REPO_ID,
        checkout_path=Path("/fake"),
        baseline_sha="base",
        head_sha="head",
        detector_version=DETECTOR_V1,
    )

    mock_cache.put.assert_not_called()
    assert result.cached_verifications == 1
    assert result.new_verifications == 0
    assert len(result.findings) == 1
    assert result.findings[0].verification_status == "skipped-cache-hit"


def test_cache_hit_verified_flag_reflects_cached_status(monkeypatch):
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    from src.secrets.verified_secrets_cache import VerificationStatus
    from datetime import datetime, timezone, timedelta
    mock_cache.get.return_value = VerificationStatus(
        status="revoked",
        verified_at=datetime.now(timezone.utc),
        ttl_until=datetime.now(timezone.utc) + timedelta(days=1),
    )

    commits = [_make_commit("abc")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )
    engine = SecretsBaselineDelta(mock_cache, MagicMock(return_value=[_candidate("fake_token_12345")]))

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )
    # "revoked" status → verified=False
    assert result.findings[0].verified is False


# ── cache miss path ───────────────────────────────────────────────────────────


def test_cache_miss_calls_stub_verifier_and_caches(monkeypatch):
    """On miss, stub verifier is called and result is stored in cache."""
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    mock_cache.get.return_value = None  # cache miss

    commits = [_make_commit("sha1")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )

    secret_val = "fake_token_99999"
    mock_runner = MagicMock(return_value=[_candidate(secret_val)])
    engine = SecretsBaselineDelta(mock_cache, mock_runner)

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )

    assert result.new_verifications == 1
    assert result.cached_verifications == 0
    mock_cache.put.assert_called_once()
    put_args = mock_cache.put.call_args
    assert put_args[1]["status"] == "unverified"   # stub always returns "unverified"


def test_cache_miss_finding_has_correct_fields(monkeypatch):
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    mock_cache.get.return_value = None

    commits = [_make_commit("deadbeef")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )
    engine = SecretsBaselineDelta(
        mock_cache,
        MagicMock(return_value=[_candidate("fake_token_abc", "src/config.py", 42)]),
    )

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )

    f = result.findings[0]
    assert isinstance(f, SecretFinding)
    assert f.commit_sha == "deadbeef"
    assert f.file_path == "src/config.py"
    assert f.line == 42
    assert f.detector_id == DETECTOR_TYPE
    assert len(f.secret_hash) == 64    # sha256 hex


# ── multiple commits processed in order ──────────────────────────────────────


def test_multiple_commits_processed_in_order(monkeypatch):
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    mock_cache.get.return_value = None

    commits = [_make_commit("sha_first"), _make_commit("sha_second")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )

    mock_runner = MagicMock(return_value=[_candidate("fake_token_12345")])
    engine = SecretsBaselineDelta(mock_cache, mock_runner)

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )

    assert result.commits_scanned == 2
    assert len(result.findings) == 2
    assert result.findings[0].commit_sha == "sha_first"
    assert result.findings[1].commit_sha == "sha_second"


# ── detector version bump busts cache ────────────────────────────────────────


def test_detector_version_bump_produces_different_cache_key(monkeypatch):
    """A version change in detector_version → different versioned_id → cache miss."""
    secret_val = "fake_token_12345"
    hash_v1 = _versioned_detector_id(DETECTOR_TYPE, DETECTOR_V1)
    hash_v2 = _versioned_detector_id(DETECTOR_TYPE, DETECTOR_V2)

    assert hash_v1 != hash_v2

    calls: list[str] = []

    class TrackingCache:
        def get(self, detector_id, secret_hash):
            calls.append(("get", detector_id))
            return None

        def put(self, detector_id, secret_hash, *, status):
            calls.append(("put", detector_id))

    commits = [_make_commit("abc")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )

    engine = SecretsBaselineDelta(
        TrackingCache(),
        MagicMock(return_value=[_candidate(secret_val)]),
    )

    engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )
    engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V2,
    )

    # Both scans produce different versioned detector ids → both are cache misses
    get_detector_ids = [c[1] for c in calls if c[0] == "get"]
    assert hash_v1 in get_detector_ids
    assert hash_v2 in get_detector_ids


# ── empty scan ────────────────────────────────────────────────────────────────


def test_no_new_commits_returns_empty_result(monkeypatch):
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: [],
    )
    engine = SecretsBaselineDelta(mock_cache, MagicMock(return_value=[]))

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )

    assert isinstance(result, SecretsScanResult)
    assert result.findings == []
    assert result.commits_scanned == 0
    assert result.duration_ms >= 0


def test_commit_with_no_candidates_contributes_no_findings(monkeypatch):
    mock_cache = MagicMock(spec=VerifiedSecretsCache)
    commits = [_make_commit("abc")]
    monkeypatch.setattr(
        "src.secrets.baseline_delta.enumerate_new_commits",
        lambda *a, **kw: commits,
    )
    engine = SecretsBaselineDelta(mock_cache, MagicMock(return_value=[]))

    result = engine.scan(
        repo_id=REPO_ID, checkout_path=Path("/fake"),
        baseline_sha="base", head_sha="head", detector_version=DETECTOR_V1,
    )

    assert result.findings == []
    assert result.commits_scanned == 1
