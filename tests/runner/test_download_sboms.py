"""Tests for the rewritten download_sboms — pulls via backend_client."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

from runner.scanners.dependencies.download_sboms import download_sboms


def _mock_get_resp(status: int, body: bytes = b"") -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.content = body
    return m


def test_download_sboms_writes_files(tmp_path):
    backend = MagicMock()
    backend.list_sbom_downloads.return_value = [
        {"file": "a.cdx.json", "url": "https://minio/a"},
        {"file": "b.cdx.json", "url": "https://minio/b"},
    ]
    with patch("runner.scanners.dependencies.download_sboms.httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.get.side_effect = [
            _mock_get_resp(200, b"sbom-a"),
            _mock_get_resp(200, b"sbom-b"),
        ]
        count = download_sboms(backend_client=backend, job_id="job-1", output_dir=tmp_path)

    assert count == 2
    assert (tmp_path / "a.cdx.json").read_bytes() == b"sbom-a"
    assert (tmp_path / "b.cdx.json").read_bytes() == b"sbom-b"


def test_download_sboms_returns_zero_when_empty(tmp_path):
    backend = MagicMock()
    backend.list_sbom_downloads.return_value = []
    count = download_sboms(backend_client=backend, job_id="job-1", output_dir=tmp_path)
    assert count == 0


def test_download_sboms_continues_on_per_file_failure(tmp_path):
    backend = MagicMock()
    backend.list_sbom_downloads.return_value = [
        {"file": "good.json", "url": "https://minio/good"},
        {"file": "bad.json", "url": "https://minio/bad"},
    ]
    with patch("runner.scanners.dependencies.download_sboms.httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.get.side_effect = [
            _mock_get_resp(200, b"ok"),
            _mock_get_resp(500),
        ]
        count = download_sboms(backend_client=backend, job_id="job-1", output_dir=tmp_path)
    assert count == 1
    assert (tmp_path / "good.json").exists()
    assert not (tmp_path / "bad.json").exists()
