"""_resolve_pr_base_sha dispatches to the correct provider by SCM type."""
from __future__ import annotations

import os

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

from src.scans import service


@pytest.mark.asyncio
@pytest.mark.parametrize("scm_type", [
    "github",
    "gitlab",
    "bitbucket",
    "azure_devops",
])
async def test_dispatches_to_provider_by_source_scm_type(scm_type):
    fake_source = MagicMock(scm_type=scm_type, scm_base_url=None, repo="owner/repo")
    mock_provider = MagicMock()
    mock_provider.resolve_pr_base_sha = AsyncMock(return_value="abc123")
    with patch.object(service, "_load_source", new=AsyncMock(return_value=fake_source)), \
         patch.object(service, "resolve_pr_provider", return_value=mock_provider):
        sha = await service._resolve_pr_base_sha("source-uuid", 42, "tok")
        assert sha == "abc123"
        service.resolve_pr_provider.assert_called_once_with(fake_source)


@pytest.mark.asyncio
async def test_returns_none_when_source_unknown_or_unsupported_scm():
    fake_source = MagicMock(scm_type="unknown", scm_base_url=None)
    with patch.object(service, "_load_source", new=AsyncMock(return_value=fake_source)):
        sha = await service._resolve_pr_base_sha("source-uuid", 42, "tok")
        assert sha is None


@pytest.mark.asyncio
async def test_returns_none_when_token_empty():
    sha = await service._resolve_pr_base_sha("source-uuid", 42, "")
    assert sha is None


@pytest.mark.asyncio
async def test_returns_none_when_source_not_found():
    with patch.object(service, "_load_source", new=AsyncMock(return_value=None)):
        sha = await service._resolve_pr_base_sha("source-uuid", 42, "tok")
        assert sha is None
