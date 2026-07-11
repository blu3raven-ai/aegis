"""SSRF hardening + existence semantics for repo_url_check."""
import pytest

from src.sources.repo_url_check import repo_url_exists
from src.sources.store import SourceValidationError


def _resolve_to(monkeypatch, ip: str):
    monkeypatch.setattr(
        "src.sources.repo_url_check.socket.getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", (ip, 443))],
    )


def _mock_response(monkeypatch, status: int, ctype: str):
    class _Res:
        status_code = status
        headers = {"content-type": ctype}

    class _Client:
        def __init__(self, *a, **k):
            pass
        async def __aenter__(self):
            return self
        async def __aexit__(self, *a):
            return False
        async def get(self, *a, **k):
            return _Res()

    monkeypatch.setattr("src.sources.repo_url_check.httpx.AsyncClient", _Client)


@pytest.mark.asyncio
async def test_rejects_non_https():
    with pytest.raises(SourceValidationError):
        await repo_url_exists("http://example.com/foo/bar")


@pytest.mark.asyncio
async def test_rejects_internal_host(monkeypatch):
    _resolve_to(monkeypatch, "127.0.0.1")
    with pytest.raises(SourceValidationError):
        await repo_url_exists("https://localhost/foo/bar")


@pytest.mark.asyncio
async def test_rejects_link_local_metadata(monkeypatch):
    _resolve_to(monkeypatch, "169.254.169.254")
    with pytest.raises(SourceValidationError):
        await repo_url_exists("https://metadata.example/foo/bar")


@pytest.mark.asyncio
async def test_exists_when_smart_http_advertises(monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")
    _mock_response(monkeypatch, 200, "application/x-git-upload-pack-advertisement")
    assert await repo_url_exists("https://git.example.com/foo/bar") is True


@pytest.mark.asyncio
async def test_not_exists_on_404(monkeypatch):
    _resolve_to(monkeypatch, "93.184.216.34")
    _mock_response(monkeypatch, 404, "text/html")
    assert await repo_url_exists("https://git.example.com/foo/missing") is False
