"""Tests for secrets pool merge and lifecycle hooks."""
from __future__ import annotations

import pytest

from src.secrets.pool import merge_pool


def _make_finding(*, secret_identity: str, repo: str, fingerprint: str, run_id: str = "run-1") -> dict:
    return {
        "secretIdentity": secret_identity,
        "fingerprint": fingerprint,
        "organization": "acme",
        "repository": repo,
        "source": "trufflehog",
        "detector": "generic-api-key",
        "filePath": "src/config.py",
        "line": 10,
        "commit": "abc123",
        "detectedAt": "2026-05-01T00:00:00Z",
        "classificationHistory": [{"runId": run_id, "scannedAt": "2026-05-01T00:00:00Z"}],
        "reviewStatus": "new",
    }


def test_merge_pool_splits_same_secret_across_repos():
    # Same secret in two repos → one finding per repo (each scoped to its repo
    # asset), sharing secretIdentity so the UI can group them.
    findings = [
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-a1"),
        _make_finding(secret_identity="sha-aaa", repo="repo-b", fingerprint="fp-a2"),
    ]
    result = merge_pool(findings, [])
    assert len(result) == 2
    by_repo = {f["repository"]: f for f in result}
    assert set(by_repo) == {"repo-a", "repo-b"}
    assert all(f["secretIdentity"] == "sha-aaa" for f in result)
    # Each finding's locations stay within its own repo.
    for repo, f in by_repo.items():
        assert {loc["repository"] for loc in f["locations"]} == {repo}


def test_merge_pool_aggregates_same_secret_same_repo():
    # Same secret, same repo, different files → one finding with both locations.
    findings = [
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-1"),
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-2"),
    ]
    result = merge_pool(findings, [])
    assert len(result) == 1
    assert len(result[0]["locations"]) == 2


def test_merge_pool_different_secrets_stay_separate():
    findings = [
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-a"),
        _make_finding(secret_identity="sha-bbb", repo="repo-b", fingerprint="fp-b"),
    ]
    result = merge_pool(findings, [])
    assert len(result) == 2


def test_merge_pool_carries_forward_classification_history():
    previous = [
        {
            "secretIdentity": "sha-aaa",
            "repository": "repo-a",
            "classificationHistory": [{"runId": "run-old", "scannedAt": "2026-04-01T00:00:00Z"}],
            "locations": [{"repository": "repo-a"}],
        }
    ]
    current = [
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-a", run_id="run-new"),
    ]
    result = merge_pool(current, previous)
    assert len(result) == 1
    history = result[0]["classificationHistory"]
    run_ids = {e["runId"] for e in history}
    assert "run-old" in run_ids
    assert "run-new" in run_ids


def test_merge_pool_deduplicates_classification_by_run_id():
    previous = [
        {
            "secretIdentity": "sha-aaa",
            "classificationHistory": [{"runId": "run-1", "scannedAt": "2026-04-01T00:00:00Z"}],
            "locations": [],
        }
    ]
    current = [
        _make_finding(secret_identity="sha-aaa", repo="repo-a", fingerprint="fp-a", run_id="run-1"),
    ]
    result = merge_pool(current, previous)
    history = result[0]["classificationHistory"]
    assert len(history) == 1  # Not duplicated


def test_merge_pool_empty_inputs():
    assert merge_pool([], []) == []


from src.secrets.lifecycle import secrets_hooks


def test_secrets_hooks_identity_key_no_org_prefix():
    raw = {"secretIdentity": "sha256_abc123", "organization": "acme"}
    key = secrets_hooks.compute_identity_key(raw)
    assert key == "sha256_abc123"
    assert "::" not in key  # No org prefix


def test_secrets_hooks_initial_state():
    assert secrets_hooks.initial_state({}) == "open"


def test_secrets_hooks_extract_repo_returns_repo():
    assert secrets_hooks.extract_repo({"repository": "some-repo"}) == "some-repo"
    assert secrets_hooks.extract_repo({}) is None


def test_secrets_hooks_extract_detail_includes_locations():
    raw = {
        "secretIdentity": "sha-aaa",
        "fingerprint": "fp-1",
        "detector": "generic-api-key",
        "source": "trufflehog",
        "locations": [{"repository": "repo-a"}],
        "classificationHistory": [{"runId": "r1"}],
        "repository": "repo-a",
        "filePath": "config.py",
        "line": 5,
        "commit": "abc",
    }
    detail = secrets_hooks.extract_detail(raw)
    assert detail["secretIdentity"] == "sha-aaa"
    assert detail["locations"] == [{"repository": "repo-a"}]
    assert detail["repository"] == "repo-a"
    assert detail["filePath"] == "config.py"


def test_secrets_hooks_should_mark_fixed_returns_false():
    assert secrets_hooks.should_mark_fixed("any-key", {}) is False


def test_secrets_hooks_should_mark_fixed_ignores_kwargs():
    assert secrets_hooks.should_mark_fixed("any-key", {"filePath": "x"}, org="acme", run_id="r1") is False
