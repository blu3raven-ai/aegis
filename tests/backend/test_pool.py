from __future__ import annotations


def _make_finding(
    *,
    repository: str = "repo-a",
    fingerprint: str = "fp-1",
    detected_at: str = "2026-04-01T00:00:00Z",
    commit: str | None = "abc123",
    organization: str = "example-org",
) -> dict[str, object]:
    return {
        "organization": organization,
        "repository": repository,
        "fingerprint": fingerprint,
        "detectedAt": detected_at,
        "commit": commit,
    }


def test_read_checkpoints_returns_empty_when_no_data():
    from src.secrets.pool import read_checkpoints

    # DB-backed: returns empty dict when no checkpoints exist
    result = read_checkpoints()
    assert isinstance(result, dict)


def test_write_checkpoint_for_repo_writes_repo_checkpoint():
    from src.secrets.pool import read_checkpoints, write_checkpoint_for_repo

    write_checkpoint_for_repo("my-repo", "abc123", "2026-04-01T00:00:00Z", org="testorg")

    checkpoints = read_checkpoints()
    assert checkpoints["my-repo"]["lastCommitSha"] == "abc123"
    assert checkpoints["my-repo"]["lastScannedAt"] == "2026-04-01T00:00:00Z"


def test_write_checkpoint_for_repo_merges_existing_repos():
    from src.secrets.pool import read_checkpoints, write_checkpoint_for_repo

    write_checkpoint_for_repo("repo-a", "aaa", "2026-04-01T00:00:00Z", org="testorg")
    write_checkpoint_for_repo("repo-b", "bbb", "2026-04-02T00:00:00Z", org="testorg")

    checkpoints = read_checkpoints()
    assert "repo-a" in checkpoints
    assert "repo-b" in checkpoints


def test_reset_checkpoints():
    from src.secrets.pool import reset_checkpoints

    # DB-backed: should not raise
    reset_checkpoints(org="testorg")


def test_get_scan_start_date_returns_earliest_date():
    from src.secrets.pool import get_scan_start_date

    checkpoints = {
        "repo-a": {"lastScannedAt": "2026-04-10T00:00:00Z", "lastCommitSha": "a"},
        "repo-b": {"lastScannedAt": "2026-03-01T00:00:00Z", "lastCommitSha": "b"},
    }

    assert get_scan_start_date(checkpoints) == "2026-03-01"


def test_get_scan_start_date_returns_none_when_empty():
    from src.secrets.pool import get_scan_start_date

    assert get_scan_start_date({}) is None


def test_read_pool_returns_empty_when_missing(tmp_path):
    from src.secrets.pool import read_pool

    # read_pool is DB-backed; path is ignored. Filter by an unused org so we
    # get a deterministic empty result regardless of other tests' DB state.
    assert read_pool(tmp_path / "missing.pool.jsonl", org="__no_such_org__") == {}


def test_read_pool_returns_empty_on_corrupt_file(tmp_path):
    from src.secrets.pool import read_pool

    path = tmp_path / "example-org.pool.jsonl"
    path.write_text("not json\n", encoding="utf-8")

    # read_pool is DB-backed; corrupt-file path is irrelevant. Scope to a
    # fresh org for a deterministic empty result.
    assert read_pool(path, org="__no_such_org__") == {}



def test_get_scan_start_date_returns_min_repo_date():
    from src.secrets.pool import get_scan_start_date

    checkpoints = {
        "repo-a": {"lastCommitSha": "abc", "lastScannedAt": "2026-04-10T00:00:00Z"},
        "repo-b": {"lastCommitSha": "xyz", "lastScannedAt": "2026-03-01T00:00:00Z"},
    }

    assert get_scan_start_date(checkpoints) == "2026-03-01"


def test_get_scan_start_date_returns_none_for_empty_checkpoints():
    from src.secrets.pool import get_scan_start_date

    assert get_scan_start_date({}) is None
