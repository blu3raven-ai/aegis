"""Tests for runner.clients.backend — thin HTTP wrapper over backend presign endpoints."""
from __future__ import annotations

import pytest
import httpx
from unittest.mock import patch, MagicMock

from runner.clients.backend import BackendClient, BackendError


@pytest.fixture
def client():
    return BackendClient(portal_url="https://backend.test", auth_token="tok")


def _mock_resp(status: int, body: dict | None = None) -> MagicMock:
    m = MagicMock()
    m.status_code = status
    m.json.return_value = body or {}
    m.text = str(body or {})
    return m


def test_presign_uploads_returns_file_to_url_map(client):
    body = {"urls": [
        {"file": "a.json", "url": "https://minio/a", "fields": {"key": "a", "policy": "p"}},
        {"file": "b.json", "url": "https://minio/b", "fields": {"key": "b", "policy": "p"}},
    ], "expiresIn": 300}
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.return_value = _mock_resp(200, body)
        result = client.presign_uploads("job-1", ["a.json", "b.json"])
    assert result == {
        "a.json": {"url": "https://minio/a", "fields": {"key": "a", "policy": "p"}},
        "b.json": {"url": "https://minio/b", "fields": {"key": "b", "policy": "p"}},
    }


def test_presign_uploads_raises_on_4xx(client):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.return_value = _mock_resp(409, {"error": "not running"})
        with pytest.raises(BackendError) as exc:
            client.presign_uploads("job-1", ["a.json"])
    assert exc.value.status == 409


def test_presign_uploads_retries_on_5xx_then_succeeds(client):
    body = {"urls": [{"file": "a.json", "url": "https://minio/a", "fields": {"key": "a"}}], "expiresIn": 300}
    with patch("httpx.Client") as mock_ctor:
        post = mock_ctor.return_value.__enter__.return_value.post
        post.side_effect = [_mock_resp(503), _mock_resp(200, body)]
        result = client.presign_uploads("job-1", ["a.json"])
    assert result == {"a.json": {"url": "https://minio/a", "fields": {"key": "a"}}}
    assert post.call_count == 2


def test_presign_uploads_raises_after_max_retries(client):
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.post.side_effect = [_mock_resp(500)] * 4
        with pytest.raises(BackendError):
            client.presign_uploads("job-1", ["a.json"])


def test_list_sbom_downloads_returns_entries(client):
    body = {"sboms": [{"file": "x.json", "url": "u"}], "count": 1, "expiresIn": 300}
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.get.return_value = _mock_resp(200, body)
        result = client.list_sbom_downloads("job-1")
    assert result == [{"file": "x.json", "url": "u"}]


def test_list_sbom_downloads_empty(client):
    body = {"sboms": [], "count": 0, "expiresIn": 300}
    with patch("httpx.Client") as mock_ctor:
        mock_ctor.return_value.__enter__.return_value.get.return_value = _mock_resp(200, body)
        result = client.list_sbom_downloads("job-1")
    assert result == []


def test_update_auth_token_swaps_bearer_header_on_next_request(client):
    """After /complete auto-rotates the token, subsequent presign calls must
    use the NEW token. Prevents 401-on-next-job regressions."""
    client.update_auth_token("new-tok")

    body = {"urls": [{"file": "a.json", "url": "u"}], "expiresIn": 300}
    captured: dict = {}
    with patch("httpx.Client") as mock_ctor:
        def capture_post(url, headers=None, json=None):
            captured["headers"] = headers
            return _mock_resp(200, body)
        mock_ctor.return_value.__enter__.return_value.post.side_effect = capture_post
        client.presign_uploads("job-1", ["a.json"])

    assert captured["headers"] == {"Authorization": "Bearer new-tok"}
