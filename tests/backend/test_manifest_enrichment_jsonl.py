"""Tests for manifest snippet enrichment in the findings.jsonl ingestion path."""
from __future__ import annotations

import pytest
import src.dependencies.scanner as scanner


def test_load_manifests_from_minio_groups_by_repo(monkeypatch):
    prefix = "dependencies/acme-org/run-1/"

    monkeypatch.setattr(scanner, "list_objects", lambda p: [
        "dependencies/acme-org/run-1/repo-a/manifests/package.json",
        "dependencies/acme-org/run-1/repo-a/manifests/src/requirements.txt",
        "dependencies/acme-org/run-1/repo-b/manifests/requirements.txt",
        # non-manifest files must be ignored
        "dependencies/acme-org/run-1/repo-a/sbom.cdx.json",
        "dependencies/acme-org/run-1/findings.jsonl",
    ])
    content_by_key = {
        "dependencies/acme-org/run-1/repo-a/manifests/package.json": b'{"lodash":"^4"}',
        "dependencies/acme-org/run-1/repo-a/manifests/src/requirements.txt": b"torch==2.0.0",
        "dependencies/acme-org/run-1/repo-b/manifests/requirements.txt": b"flask==2.0",
    }
    monkeypatch.setattr(scanner, "download_bytes", lambda k: content_by_key.get(k))

    result = scanner._load_manifests_from_minio(prefix)

    assert set(result.keys()) == {"repo-a", "repo-b"}
    assert result["repo-a"]["package.json"] == '{"lodash":"^4"}'
    assert result["repo-a"]["src/requirements.txt"] == "torch==2.0.0"
    assert result["repo-b"]["requirements.txt"] == "flask==2.0"
    # sbom and jsonl must not appear
    assert "sbom.cdx.json" not in result.get("repo-a", {})


def test_load_manifests_from_minio_skips_missing_downloads(monkeypatch):
    prefix = "dependencies/acme-org/run-1/"
    monkeypatch.setattr(scanner, "list_objects", lambda p: [
        "dependencies/acme-org/run-1/repo-a/manifests/package.json",
    ])
    monkeypatch.setattr(scanner, "download_bytes", lambda k: None)

    result = scanner._load_manifests_from_minio(prefix)
    assert result == {}


def test_load_manifests_from_minio_empty_prefix(monkeypatch):
    monkeypatch.setattr(scanner, "list_objects", lambda p: [])
    monkeypatch.setattr(scanner, "download_bytes", lambda k: None)

    result = scanner._load_manifests_from_minio("dependencies/acme-org/run-1/")
    assert result == {}


def test_load_manifests_cross_repo_no_collision(monkeypatch):
    """Two repos with the same manifest filename must not cross-pollinate."""
    prefix = "dependencies/acme-org/run-1/"
    monkeypatch.setattr(scanner, "list_objects", lambda p: [
        "dependencies/acme-org/run-1/backend/manifests/requirements.txt",
        "dependencies/acme-org/run-1/frontend/manifests/requirements.txt",
    ])
    content_by_key = {
        "dependencies/acme-org/run-1/backend/manifests/requirements.txt": b"django==4.0",
        "dependencies/acme-org/run-1/frontend/manifests/requirements.txt": b"flask==2.0",
    }
    monkeypatch.setattr(scanner, "download_bytes", lambda k: content_by_key.get(k))

    result = scanner._load_manifests_from_minio(prefix)

    assert result["backend"]["requirements.txt"] == "django==4.0"
    assert result["frontend"]["requirements.txt"] == "flask==2.0"
