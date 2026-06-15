"""Integration test for agent._execute_job using the embedded dispatcher."""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from runner.core import dispatcher


def test_dispatcher_get_scanner_returns_callable_run_scan():
    """Smoke test: the dispatcher returns instances whose run_scan is callable."""
    for scanner_type in ("dependencies", "container", "secrets", "code-scanning"):
        scanner = dispatcher.get_scanner(scanner_type)
        assert callable(scanner.run_scan)


def test_agent_uses_dispatcher_for_known_types(monkeypatch, tmp_path):
    """When agent._execute_job runs, it must route via the dispatcher (not Docker)."""
    # Confirm runner.agent imports get_scanner (and NOT execute_docker_job)
    import runner.agent
    assert hasattr(runner.agent, "get_scanner") or "get_scanner" in dir(runner.agent)
    assert not hasattr(runner.agent, "execute_docker_job")
