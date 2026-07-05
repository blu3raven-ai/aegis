"""Tests for the hardened subprocess wrapper."""
from __future__ import annotations

import os
import threading
import time

import pytest

from runner.scanners._subprocess import (
    ScannerSubprocessError,
    ScannerTimeoutError,
    run_tool,
)


def test_run_tool_success_returns_stdout():
    rc, stdout, stderr = run_tool(["echo", "hello"])
    assert rc == 0
    assert stdout.strip() == "hello"


def test_run_tool_nonzero_exit_returns_code():
    rc, stdout, stderr = run_tool(["sh", "-c", "exit 7"])
    assert rc == 7


def test_run_tool_timeout_raises():
    with pytest.raises(ScannerTimeoutError):
        run_tool(["sleep", "10"], timeout=0.5)


def test_run_tool_rejects_shell_string():
    with pytest.raises(TypeError):
        run_tool("echo hello")  # type: ignore[arg-type]


def test_run_tool_cancel_event_kills_process():
    cancel = threading.Event()

    def trigger():
        time.sleep(0.3)
        cancel.set()

    threading.Thread(target=trigger, daemon=True).start()
    rc, stdout, stderr = run_tool(["sleep", "10"], cancel_event=cancel, kill_grace_s=1.0)
    assert rc == 137


def test_run_tool_does_not_deadlock_on_large_stdout():
    """Regression test for pipe-fill deadlock — child writes >64KB to stdout."""
    script = 'import sys; sys.stdout.write("x" * 300_000)'
    rc, stdout, stderr = run_tool(["python3", "-c", script], timeout=10)
    assert rc == 0
    assert len(stdout) == 300_000


def test_run_tool_captures_both_streams_when_chatty():
    """Regression: large stderr should not block stdout (and vice versa)."""
    script = (
        'import sys;'
        'sys.stdout.write("o" * 100_000);'
        'sys.stderr.write("e" * 100_000)'
    )
    rc, stdout, stderr = run_tool(["python3", "-c", script], timeout=10)
    assert rc == 0
    assert len(stdout) == 100_000
    assert len(stderr) == 100_000


def test_run_tool_drop_env_removes_specified_vars(monkeypatch):
    """drop_env should remove variables from the inherited environment."""
    monkeypatch.setenv("LEAKING_TOKEN", "SECRET_VALUE")
    rc, stdout, _ = run_tool(
        ["sh", "-c", "echo present=${LEAKING_TOKEN:-absent}"],
        drop_env=["LEAKING_TOKEN"],
    )
    assert rc == 0
    assert "present=absent" in stdout


def test_run_tool_drop_env_does_not_affect_parent_env(monkeypatch):
    """drop_env affects the child only; parent env untouched."""
    monkeypatch.setenv("KEEP_ME", "yes")
    run_tool(["echo", "x"], drop_env=["KEEP_ME"])
    assert os.environ.get("KEEP_ME") == "yes"
