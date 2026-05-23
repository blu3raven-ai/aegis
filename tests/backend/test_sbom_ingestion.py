"""Tests for SBOM ingestion during dependency scan processing."""
from __future__ import annotations

from unittest.mock import patch

from src.dependencies.scanner import _ingest_sboms_from_minio


SAMPLE_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {
            "name": "lodash",
            "version": "4.17.21",
            "purl": "pkg:npm/lodash@4.17.21",
            "properties": [{"name": "scanner:source", "value": "syft"}],
        },
        {
            "name": "express",
            "version": "4.18.2",
            "purl": "pkg:npm/express@4.18.2",
            "properties": [{"name": "scanner:source", "value": "cdxgen"}],
        },
    ],
}


@patch("src.dependencies.scanner.upsert_sbom")
@patch("src.shared.object_store.download_json", return_value=SAMPLE_SBOM)
@patch("src.shared.object_store.list_objects", return_value=[
    "dependencies/acme-org/run-1/my-repo/sbom.cdx.json",
    "dependencies/acme-org/run-1/my-repo/findings.json",
    "dependencies/acme-org/run-1/other-repo/sbom.cdx.json",
])
def test_ingest_sboms_from_minio_calls_upsert_for_each_repo(mock_list, mock_download, mock_upsert):
    _ingest_sboms_from_minio("acme-org", "run-1", "dependencies/acme-org/run-1/")

    # Should only process sbom.cdx.json files, not findings.json
    assert mock_upsert.call_count == 2

    # Check repo names extracted from keys
    repos = sorted(call[1]["repo"] for call in mock_upsert.call_args_list)
    assert repos == ["my-repo", "other-repo"]


@patch("src.dependencies.scanner.upsert_sbom")
@patch("src.shared.object_store.download_json", return_value=SAMPLE_SBOM)
@patch("src.shared.object_store.list_objects", return_value=[
    "dependencies/acme-org/run-1/my-repo/findings.json",
])
def test_ingest_sboms_skips_when_no_sbom_files(mock_list, mock_download, mock_upsert):
    _ingest_sboms_from_minio("acme-org", "run-1", "dependencies/acme-org/run-1/")

    assert mock_upsert.call_count == 0
    assert mock_download.call_count == 0


@patch("src.dependencies.scanner.upsert_sbom")
@patch("src.shared.object_store.download_json", return_value=None)
@patch("src.shared.object_store.list_objects", return_value=[
    "dependencies/acme-org/run-1/my-repo/sbom.cdx.json",
])
def test_ingest_sboms_skips_when_download_returns_none(mock_list, mock_download, mock_upsert):
    _ingest_sboms_from_minio("acme-org", "run-1", "dependencies/acme-org/run-1/")

    assert mock_upsert.call_count == 0


@patch("src.dependencies.scanner.upsert_sbom", side_effect=Exception("DB error"))
@patch("src.shared.object_store.download_json", return_value=SAMPLE_SBOM)
@patch("src.shared.object_store.list_objects", return_value=[
    "dependencies/acme-org/run-1/repo-a/sbom.cdx.json",
    "dependencies/acme-org/run-1/repo-b/sbom.cdx.json",
])
def test_ingest_sboms_continues_on_error(mock_list, mock_download, mock_upsert):
    """If one repo fails, the others should still be attempted."""
    _ingest_sboms_from_minio("acme-org", "run-1", "dependencies/acme-org/run-1/")

    assert mock_upsert.call_count == 2


@patch("src.dependencies.scanner.upsert_sbom")
@patch("src.shared.object_store.download_json", return_value=SAMPLE_SBOM)
@patch("src.shared.object_store.list_objects", return_value=[
    "dependencies/acme-org/run-1/sbom.cdx.json",
])
def test_ingest_sboms_skips_short_key_paths(mock_list, mock_download, mock_upsert):
    """Keys with fewer than 5 parts (no repo segment) should be skipped."""
    _ingest_sboms_from_minio("acme-org", "run-1", "dependencies/acme-org/run-1/")

    assert mock_upsert.call_count == 0
