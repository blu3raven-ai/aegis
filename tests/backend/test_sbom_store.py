import pytest
from src.dependencies.sbom_store import upsert_sbom, read_sbom, read_all_sboms_for_org


SAMPLE_SBOM = {
    "artifacts": [
        {
            "name": "lodash",
            "version": "4.17.20",
            "type": "npm",
            "locations": [{"path": "/package-lock.json"}],
        }
    ]
}

SAMPLE_MANIFESTS = {
    "package-lock.json": '{"dependencies": {"lodash": "4.17.20"}}'
}


def test_upsert_sbom_creates_new():
    upsert_sbom(
        org="testorg",
        repo="testorg/myrepo",
        commit_sha="abc1234567890abcdef1234567890abcdef12345",
        sbom=SAMPLE_SBOM,
        manifests=SAMPLE_MANIFESTS,
        run_id="run-001",
    )
    result = read_sbom("testorg", "testorg/myrepo")
    assert result is not None
    assert result["commit_sha"] == "abc1234567890abcdef1234567890abcdef12345"
    assert result["sbom"]["artifacts"][0]["name"] == "lodash"
    assert "package-lock.json" in result["manifests"]


def test_upsert_sbom_replaces_existing():
    upsert_sbom(org="testorg", repo="testorg/myrepo", commit_sha="aaa", sbom={"v": 1}, manifests={}, run_id="run-001")
    upsert_sbom(org="testorg", repo="testorg/myrepo", commit_sha="bbb", sbom={"v": 2}, manifests={}, run_id="run-002")
    result = read_sbom("testorg", "testorg/myrepo")
    assert result["commit_sha"] == "bbb"
    assert result["sbom"]["v"] == 2


def test_read_sbom_missing_returns_none():
    result = read_sbom("testorg", "no-such-repo")
    assert result is None


def test_read_all_sboms_for_org():
    upsert_sbom(org="org1", repo="org1/repo-a", commit_sha="aaa", sbom={"a": 1}, manifests={}, run_id="run-001")
    upsert_sbom(org="org1", repo="org1/repo-b", commit_sha="bbb", sbom={"b": 1}, manifests={}, run_id="run-001")
    results = read_all_sboms_for_org("org1")
    assert len(results) >= 2
    repos = {r["repo"] for r in results}
    assert "org1/repo-a" in repos
    assert "org1/repo-b" in repos
