"""Unit tests for on-demand PoC generation (LLM call mocked — no network)."""
from __future__ import annotations

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


_OK = "```python\nprint('pwned')\n```"


@pytest.mark.asyncio
async def test_generate_poc_returns_parsed_script():
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_chat(_OK))):
        out = await generate_poc({"id": 42, "title": "x"}, api_key="k",
                                 base_url="https://api.openai.com/v1", model="m")
    assert out == {"poc_script": "print('pwned')", "poc_filename": "finding-42-poc.py", "poc_language": "python"}


@pytest.mark.asyncio
async def test_generate_poc_extracts_from_messy_reasoning_output():
    # Reasoning models wrap the script in <think> blocks + prose; the filename
    # must be derived (never leak the model's junk) and the script clean.
    messy = (
        "<think>planning the poc, json5 blah</think>\n"
        "Here is the script:\n"
        "```python3\n#!/usr/bin/env python3\nprint('marker')\n```\n"
        "Done. Final response ready."
    )
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_chat(messy))):
        out = await generate_poc({"id": 7, "title": "x"}, api_key="k",
                                 base_url="https://api.openai.com/v1", model="m")
    assert out["poc_language"] == "python"
    assert out["poc_filename"] == "finding-7-poc.py"
    assert out["poc_script"].startswith("#!/usr/bin/env python3")
    assert "<think>" not in out["poc_script"] and "Final response" not in out["poc_script"]


@pytest.mark.asyncio
async def test_generate_poc_forwards_user_guidance():
    client = _client(_chat(_OK))
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=client):
        await generate_poc({"title": "x"}, api_key="k",
                           base_url="https://api.openai.com/v1", model="m",
                           instruction="target the /admin route")
    inner = client.__aenter__.return_value
    sent = inner.post.call_args.kwargs["json"]
    user_msg = sent["messages"][1]["content"]
    assert "user_guidance" in user_msg
    assert "target the /admin route" in user_msg


@pytest.mark.asyncio
async def test_generate_poc_omits_guidance_when_absent():
    client = _client(_chat(_OK))
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=client):
        await generate_poc({"title": "x"}, api_key="k",
                           base_url="https://api.openai.com/v1", model="m")
    inner = client.__aenter__.return_value
    sent = inner.post.call_args.kwargs["json"]
    assert "user_guidance" not in sent["messages"][1]["content"]


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
    empty = "```python\n   \n```"
    with patch("src.findings.poc_generation.assert_sendable_url"), \
         patch("src.findings.poc_generation.httpx.AsyncClient", return_value=_client(_chat(empty))):
        with pytest.raises(PocGenerationError):
            await generate_poc({"title": "x"}, api_key="k",
                               base_url="https://api.openai.com/v1", model="m")
