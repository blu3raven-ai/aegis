"""Unit tests for on-demand PoC generation (LLM call mocked — no network)."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.findings.poc_generation import PocGenerationError, generate_poc
from src.shared.url_guard import UnsafeURLError


def _resp(status: int, payload: dict) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload
    return r


def _client(resp: MagicMock) -> MagicMock:
    """A fake httpx.AsyncClient(...) whose `async with` yields a poster."""
    inner = MagicMock()
    inner.post = AsyncMock(return_value=resp)
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=inner)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _chat(content: str) -> MagicMock:
    return _resp(200, {"choices": [{"message": {"content": content}}]})


_OK = json.dumps({"poc_script": "print('pwned')", "poc_filename": "poc.py", "poc_language": "python"})


@pytest.mark.asyncio
async def test_generate_poc_returns_parsed_script():
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_chat(_OK))):
        out = await generate_poc({"title": "x"}, api_key="k",
                                 base_url="https://api.openai.com/v1", model="m")
    assert out == {"poc_script": "print('pwned')", "poc_filename": "poc.py", "poc_language": "python"}


@pytest.mark.asyncio
async def test_generate_poc_requires_api_key():
    with pytest.raises(PocGenerationError):
        await generate_poc({"title": "x"}, api_key="", base_url="https://api.openai.com/v1", model="m")


@pytest.mark.asyncio
async def test_generate_poc_rejects_unsafe_url():
    with patch("src.findings.poc_generation.assert_sendable_url",
               side_effect=UnsafeURLError("blocked")):
        with pytest.raises(PocGenerationError):
            await generate_poc({"title": "x"}, api_key="k",
                               base_url="http://169.254.169.254", model="m")


@pytest.mark.asyncio
async def test_generate_poc_auth_rejected_maps_to_error():
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_resp(401, {}))):
        with pytest.raises(PocGenerationError):
            await generate_poc({"title": "x"}, api_key="k",
                               base_url="https://api.openai.com/v1", model="m")


@pytest.mark.asyncio
async def test_generate_poc_empty_script_errors():
    empty = json.dumps({"poc_script": "   ", "poc_filename": "", "poc_language": ""})
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_chat(empty))):
        with pytest.raises(PocGenerationError):
            await generate_poc({"title": "x"}, api_key="k",
                               base_url="https://api.openai.com/v1", model="m")
