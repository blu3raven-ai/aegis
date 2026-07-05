"""Tests for runner.clients.uploader — single-file presigned multipart POST."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from runner.clients.uploader import post_to_url, URL_EXPIRED_MARKER

_FIELDS = {"key": "tool/org/run/f.json", "policy": "b64", "x-amz-signature": "sig"}


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


def test_post_to_url_success(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        post = mock_ctor.return_value.__enter__.return_value.post
        post.return_value = _mock_resp(204)  # S3 POST success is 204 No Content
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS) == "ok"
        # Policy fields go in the form body; the file part is named "file".
        _, kwargs = post.call_args
        assert kwargs["data"] == _FIELDS
        assert "file" in kwargs["files"]


def test_post_to_url_returns_expired_on_403_signature(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.return_value = _mock_resp(
            403, "<Error><Code>SignatureDoesNotMatch</Code></Error>"
        )
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS) == URL_EXPIRED_MARKER


def test_post_to_url_returns_expired_on_403_expired(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.return_value = _mock_resp(
            403, "Request has expired"
        )
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS) == URL_EXPIRED_MARKER


def test_post_to_url_oversized_is_a_hard_fail_not_expiry(tmp_file):
    # The store rejects an over-cap upload with EntityTooLarge — a real failure,
    # not a signature/expiry case, so it must NOT be retried as expired.
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.return_value = _mock_resp(
            403, "<Error><Code>EntityTooLarge</Code></Error>"
        )
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS) == "fail"


def test_post_to_url_retries_on_500_then_succeeds(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        post = mock_ctor.return_value.__enter__.return_value.post
        post.side_effect = [_mock_resp(503), _mock_resp(204)]
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS, _sleep=lambda s: None) == "ok"


def test_post_to_url_fails_after_max_retries(tmp_file):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.side_effect = [_mock_resp(500)] * 5
        assert post_to_url(tmp_file, "https://minio/scans", _FIELDS, _sleep=lambda s: None) == "fail"
