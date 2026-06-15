"""Tests for runner.clients.uploader — single-file PUT to a presigned URL."""
from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import httpx

from runner.clients.uploader import put_to_url, URL_EXPIRED_MARKER


@pytest.fixture
def tmp_file(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('{"hello": "world"}')
    return p


def _mock_resp(status: int, text: str = "") -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.text = text
    return m


def test_put_to_url_success(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.put.return_value = _mock_resp(200)
        assert put_to_url(tmp_file, "https://minio/key?sig=xyz") == "ok"


def test_put_to_url_returns_expired_on_403_signature(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.put.return_value = _mock_resp(
            403, "<Error><Code>SignatureDoesNotMatch</Code></Error>"
        )
        assert put_to_url(tmp_file, "https://minio/key?sig=xyz") == URL_EXPIRED_MARKER


def test_put_to_url_returns_expired_on_403_expired(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.put.return_value = _mock_resp(
            403, "Request has expired"
        )
        assert put_to_url(tmp_file, "https://minio/key?sig=xyz") == URL_EXPIRED_MARKER


def test_put_to_url_retries_on_500_then_succeeds(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        put = mock_ctor.return_value.__enter__.return_value.put
        put.side_effect = [_mock_resp(503), _mock_resp(200)]
        assert put_to_url(tmp_file, "https://minio/key", _sleep=lambda s: None) == "ok"


def test_put_to_url_fails_after_max_retries(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.put.side_effect = [_mock_resp(500)] * 5
        assert put_to_url(tmp_file, "https://minio/key", _sleep=lambda s: None) == "fail"
