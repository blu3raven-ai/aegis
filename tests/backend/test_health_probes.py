"""Tests for the health probes module — each probe is exercised in isolation."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.health.probes import (
    ProbeResult,
    probe_argus,
    probe_connected_runners,
    probe_minio,
    probe_postgres,
    probe_recent_scans,
    run_all_probes,
)


class TestProbePostgres:
    @pytest.mark.asyncio
    async def test_ok_when_query_succeeds(self):
        fake_session = AsyncMock()
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_postgres()
        assert result.name == "postgres"
        assert result.status == "ok"
        assert result.error is None

    @pytest.mark.asyncio
    async def test_fail_when_db_raises(self):
        fake_session = AsyncMock()
        fake_session.execute.side_effect = RuntimeError("connection refused")
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_postgres()
        assert result.status == "fail"
        assert "connection refused" in result.error


class TestProbeMinio:
    @pytest.mark.asyncio
    async def test_ok_when_list_buckets_succeeds(self, monkeypatch):
        monkeypatch.setenv("S3_ENDPOINT", "http://localhost:9000")
        with patch("boto3.client") as mock_boto:
            mock_s3 = MagicMock()
            mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "scans"}, {"Name": "reports"}]}
            mock_boto.return_value = mock_s3
            result = await probe_minio()
        assert result.status == "ok"
        assert result.details["bucket_count"] == 2

    @pytest.mark.asyncio
    async def test_fail_when_client_raises(self, monkeypatch):
        monkeypatch.setenv("S3_ENDPOINT", "http://localhost:9000")
        with patch("boto3.client") as mock_boto:
            mock_boto.side_effect = Exception("endpoint unreachable")
            result = await probe_minio()
        assert result.status == "fail"


class TestProbeConnectedRunners:
    def _make_session_cm(self, scalar_value: int):
        fake_result = MagicMock()
        fake_result.scalar_one.return_value = scalar_value
        fake_session = AsyncMock()
        fake_session.execute.return_value = fake_result
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        return fake_cm

    @pytest.mark.asyncio
    async def test_ok_when_connected_runner_exists(self):
        with patch("src.db.engine.async_session_factory", return_value=self._make_session_cm(2)):
            result = await probe_connected_runners()
        assert result.name == "connected_runners"
        assert result.status == "ok"
        assert result.details["connected_count"] == 2

    @pytest.mark.asyncio
    async def test_degraded_when_no_runners_connected(self):
        with patch("src.db.engine.async_session_factory", return_value=self._make_session_cm(0)):
            result = await probe_connected_runners()
        assert result.status == "degraded"
        assert result.details["connected_count"] == 0

    @pytest.mark.asyncio
    async def test_fail_when_db_raises(self):
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(side_effect=RuntimeError("connection refused"))
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_connected_runners()
        assert result.status == "fail"
        assert "connection refused" in result.error


class TestProbeRecentScans:
    @pytest.mark.asyncio
    async def test_ok_when_high_success_rate(self):
        fake_row = MagicMock()
        fake_row.total = 10
        fake_row.succeeded = 9
        fake_result = MagicMock()
        fake_result.one.return_value = fake_row
        fake_session = AsyncMock()
        fake_session.execute.return_value = fake_result
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_recent_scans()
        assert result.status == "ok"
        assert result.details["success_rate"] == 0.9

    @pytest.mark.asyncio
    async def test_degraded_when_low_success_rate(self):
        fake_row = MagicMock()
        fake_row.total = 10
        fake_row.succeeded = 7
        fake_result = MagicMock()
        fake_result.one.return_value = fake_row
        fake_session = AsyncMock()
        fake_session.execute.return_value = fake_result
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_recent_scans()
        assert result.status == "degraded"
        assert result.details["success_rate"] == 0.7

    @pytest.mark.asyncio
    async def test_ok_when_no_scans_in_24h(self):
        fake_row = MagicMock()
        fake_row.total = 0
        fake_row.succeeded = None
        fake_result = MagicMock()
        fake_result.one.return_value = fake_row
        fake_session = AsyncMock()
        fake_session.execute.return_value = fake_result
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_recent_scans()
        assert result.status == "ok"
        assert result.details["success_rate"] is None

    @pytest.mark.asyncio
    async def test_fail_when_db_raises(self):
        fake_session = AsyncMock()
        fake_session.execute.side_effect = RuntimeError("table missing")
        fake_cm = MagicMock()
        fake_cm.__aenter__ = AsyncMock(return_value=fake_session)
        fake_cm.__aexit__ = AsyncMock(return_value=False)
        with patch("src.db.engine.async_session_factory", return_value=fake_cm):
            result = await probe_recent_scans()
        assert result.status == "fail"
        assert "table missing" in result.error


class TestProbeArgus:
    @pytest.mark.asyncio
    async def test_skipped_when_no_endpoint(self, monkeypatch):
        monkeypatch.delenv("ARGUS_ENDPOINT", raising=False)
        result = await probe_argus()
        assert result.status == "skipped"

    @pytest.mark.asyncio
    async def test_ok_when_ping_returns_2xx(self, monkeypatch):
        monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await probe_argus()
        assert result.status == "ok"
        assert result.details["status_code"] == 200

    @pytest.mark.asyncio
    async def test_degraded_when_server_error(self, monkeypatch):
        monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await probe_argus()
        assert result.status == "degraded"

    @pytest.mark.asyncio
    async def test_degraded_on_timeout(self, monkeypatch):
        import httpx as _httpx
        monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
        mock_client = AsyncMock()
        mock_client.get.side_effect = _httpx.TimeoutException("timeout")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await probe_argus()
        assert result.status == "degraded"
        assert result.error == "request timeout"

    @pytest.mark.asyncio
    async def test_fail_on_connection_error(self, monkeypatch):
        import httpx as _httpx
        monkeypatch.setenv("ARGUS_ENDPOINT", "https://argus.example.com")
        mock_client = AsyncMock()
        mock_client.get.side_effect = _httpx.ConnectError("connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await probe_argus()
        assert result.status == "fail"


class TestRunAllProbes:
    @pytest.mark.asyncio
    async def test_returns_all_probes(self):
        ok = ProbeResult(name="x", status="ok", duration_ms=1, details={})
        async def _ok(*_): return ok
        with patch("src.health.probes.probe_postgres", _ok), \
             patch("src.health.probes.probe_minio", _ok), \
             patch("src.health.probes.probe_connected_runners", _ok), \
             patch("src.health.probes.probe_recent_scans", _ok), \
             patch("src.health.probes.probe_argus", _ok):
            results = await run_all_probes()
        assert len(results) == 6
        assert all(isinstance(r, ProbeResult) for r in results)

    @pytest.mark.asyncio
    async def test_one_failure_does_not_prevent_others(self):
        ok = ProbeResult(name="x", status="ok", duration_ms=1, details={})
        async def _ok(*_): return ok
        async def _boom(*_): raise RuntimeError("kaboom")
        with patch("src.health.probes.probe_postgres", _boom), \
             patch("src.health.probes.probe_minio", _ok), \
             patch("src.health.probes.probe_connected_runners", _ok), \
             patch("src.health.probes.probe_recent_scans", _ok), \
             patch("src.health.probes.probe_argus", _ok):
            results = await run_all_probes()
        assert len(results) == 6
        postgres_result = next(r for r in results if r.name == "postgres")
        assert postgres_result.status == "fail"
        assert "kaboom" in (postgres_result.error or "")

    @pytest.mark.asyncio
    async def test_timeout_produces_fail_result(self):
        ok = ProbeResult(name="x", status="ok", duration_ms=1, details={})
        async def _ok(*_): return ok
        call_count = 0
        async def _fake_wait_for(coro, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                coro.close()
                raise asyncio.TimeoutError()
            return await coro
        with patch("src.health.probes.asyncio.wait_for", side_effect=_fake_wait_for):
            with patch("src.health.probes.probe_postgres", _ok), \
                 patch("src.health.probes.probe_minio", _ok), \
                 patch("src.health.probes.probe_connected_runners", _ok), \
                 patch("src.health.probes.probe_recent_scans", _ok), \
                 patch("src.health.probes.probe_argus", _ok):
                results = await run_all_probes()
        postgres_result = next(r for r in results if r.name == "postgres")
        assert postgres_result.status == "fail"
        assert postgres_result.error == "probe timeout"
        assert postgres_result.duration_ms == 5000


class TestProbeDisk:
    @pytest.mark.asyncio
    async def test_ok_when_ample_free_space(self, monkeypatch):
        from src.health import probes
        import shutil
        monkeypatch.setattr(shutil, "disk_usage", lambda p: type("U", (), {"free": 90, "total": 100})())
        r = await probes.probe_disk()
        assert r.name == "disk"
        assert r.status == "ok"
        assert r.details["percent_free"] == 90.0

    @pytest.mark.asyncio
    async def test_degraded_below_warn_threshold(self, monkeypatch):
        from src.health import probes
        import shutil
        monkeypatch.setattr(shutil, "disk_usage", lambda p: type("U", (), {"free": 10, "total": 100})())
        r = await probes.probe_disk()
        assert r.status == "degraded"

    @pytest.mark.asyncio
    async def test_fail_below_fail_threshold(self, monkeypatch):
        from src.health import probes
        import shutil
        monkeypatch.setattr(shutil, "disk_usage", lambda p: type("U", (), {"free": 2, "total": 100})())
        r = await probes.probe_disk()
        assert r.status == "fail"
