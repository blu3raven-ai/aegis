"""submit_ci_scan plumbs BASE_SHA + SCAN_SCOPE into _dispatch_scanner_jobs."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)


def _fake_get_session():
    """Return an asynccontextmanager that yields a stub session.

    The stub records add() calls but commit() is a no-op; submit_ci_scan only
    needs the row to be added and committed without raising.
    """
    class _Session:
        def add(self, _row):
            pass

        async def commit(self):
            pass

    @asynccontextmanager
    async def _ctx():
        yield _Session()

    return _ctx


@pytest.mark.asyncio
async def test_pr_triggered_scan_resolves_base_sha_and_marks_diff_scoped():
    """When pr_number is set, submit_ci_scan resolves the base SHA and dispatches diff_scoped."""
    from src.scans import service

    captured: dict = {}

    def fake_dispatch(scan_id, source_id, commit_sha, scanners, org, *, base_sha, scan_scope):
        captured["base_sha"] = base_sha
        captured["scan_scope"] = scan_scope

    with (
        patch.object(service, "_dispatch_scanner_jobs", side_effect=fake_dispatch),
        patch.object(service, "get_session", _fake_get_session()),
        patch.object(service, "_resolve_pr_base_sha", new=AsyncMock(return_value="deadbeef")),
        patch("src.shared.config.get_token_for_org", return_value="t"),
    ):
        await service.submit_ci_scan(
            org="acme-org",
            source_id="acme-org/repo",
            commit_sha="head1",
            branch="feature/x",
            pr_number=42,
            api_key_id=1,
        )

    assert captured["scan_scope"] == "diff_scoped"
    assert captured["base_sha"] == "deadbeef"


@pytest.mark.asyncio
async def test_non_pr_scan_uses_full_tree():
    from src.scans import service

    captured: dict = {}

    def fake_dispatch(scan_id, source_id, commit_sha, scanners, org, *, base_sha, scan_scope):
        captured["base_sha"] = base_sha
        captured["scan_scope"] = scan_scope

    with (
        patch.object(service, "_dispatch_scanner_jobs", side_effect=fake_dispatch),
        patch.object(service, "get_session", _fake_get_session()),
    ):
        await service.submit_ci_scan(
            org="acme-org",
            source_id="acme-org/repo",
            commit_sha="head1",
            branch="main",
            pr_number=None,
            api_key_id=1,
        )

    assert captured["scan_scope"] == "full_tree"
    assert captured["base_sha"] is None


@pytest.mark.asyncio
async def test_pr_scan_falls_back_to_full_tree_when_base_sha_unresolvable():
    from src.scans import service

    captured: dict = {}

    def fake_dispatch(scan_id, source_id, commit_sha, scanners, org, *, base_sha, scan_scope):
        captured["base_sha"] = base_sha
        captured["scan_scope"] = scan_scope

    with (
        patch.object(service, "_dispatch_scanner_jobs", side_effect=fake_dispatch),
        patch.object(service, "get_session", _fake_get_session()),
        patch.object(service, "_resolve_pr_base_sha", new=AsyncMock(return_value=None)),
        patch("src.shared.config.get_token_for_org", return_value="t"),
    ):
        await service.submit_ci_scan(
            org="acme-org",
            source_id="acme-org/repo",
            commit_sha="head1",
            branch="feature/x",
            pr_number=42,
            api_key_id=1,
        )

    assert captured["scan_scope"] == "full_tree"
    assert captured["base_sha"] is None
