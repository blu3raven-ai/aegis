"""Hardened subprocess wrapper used by every scanner module.

Centralises: list-form args (no shell), stdin=DEVNULL, working directory,
wall-clock timeout, and cooperative cancellation via threading.Event.

Cancelled subprocesses are terminated then killed; the returned exit code
is normalised to 137 (matching Docker's SIGKILL exit code convention so
the agent's existing 137-handling continues to work)."""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Sequence

logger = logging.getLogger(__name__)


class ScannerSubprocessError(RuntimeError):
    """Raised when a subprocess fails in a way the caller should handle."""


class ScannerTimeoutError(ScannerSubprocessError):
    """Raised when a subprocess exceeds its wall-clock timeout."""


CANCELLED_EXIT_CODE = 137
"""Exit code returned by run_tool when cancelled.

Matches Docker's SIGKILL exit code convention (128 + SIGKILL=9 = 137).
The runner agent's existing cancellation handling branches on this value
to distinguish user-initiated cancel from real failures."""

_POLL_INTERVAL_S = 0.2


def _read_stream(stream, chunks: list[str], done: threading.Event) -> None:
    try:
        for line in iter(stream.readline, ""):
            chunks.append(line)
    except (ValueError, OSError):
        pass
    finally:
        done.set()


def run_tool(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    cwd: Path | str | None = None,
    env: dict[str, str] | None = None,
    drop_env: Sequence[str] | None = None,
    cancel_event: threading.Event | None = None,
    kill_grace_s: float = 5.0,
    capture_output: bool = True,
) -> tuple[int, str, str]:
    """Run a tool as a hardened subprocess.

    Returns (returncode, stdout, stderr). Raises ScannerTimeoutError on timeout.
    On cancel: terminates then kills, returns rc=137.

    drop_env removes named variables from the child's environment without
    mutating the parent process env — used to keep credentials away from
    untrusted tooling (e.g. SBOM generators running lockfile scripts).
    """
    if not isinstance(args, (list, tuple)):
        raise TypeError(f"args must be a list/tuple, got {type(args).__name__}")

    full_env = os.environ.copy()
    if env:
        full_env.update(env)
    if drop_env:
        for var in drop_env:
            full_env.pop(var, None)

    # Without a cancel_event there is nothing to poll for, so the plain blocking
    # call is enough — subprocess.run drains both pipes via communicate(), so it
    # neither deadlocks on large output nor needs the reader threads below.
    if cancel_event is None:
        try:
            completed = subprocess.run(
                list(args),
                cwd=str(cwd) if cwd else None,
                env=full_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScannerTimeoutError(
                f"{args[0]} exceeded timeout of {timeout}s"
            ) from exc
        return completed.returncode, completed.stdout or "", completed.stderr or ""

    proc = subprocess.Popen(
        list(args),
        cwd=str(cwd) if cwd else None,
        env=full_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture_output else None,
        stderr=subprocess.PIPE if capture_output else None,
        text=True,
        shell=False,
    )

    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []
    stdout_done = threading.Event()
    stderr_done = threading.Event()
    stdout_thread: threading.Thread | None = None
    stderr_thread: threading.Thread | None = None

    if capture_output and proc.stdout is not None:
        stdout_thread = threading.Thread(
            target=_read_stream,
            args=(proc.stdout, stdout_chunks, stdout_done),
            daemon=True,
        )
        stdout_thread.start()
    else:
        stdout_done.set()

    if capture_output and proc.stderr is not None:
        stderr_thread = threading.Thread(
            target=_read_stream,
            args=(proc.stderr, stderr_chunks, stderr_done),
            daemon=True,
        )
        stderr_thread.start()
    else:
        stderr_done.set()

    def _finalize(rc: int) -> tuple[int, str, str]:
        join_timeout = max(kill_grace_s + 1, 1.0)
        if stdout_thread is not None:
            stdout_thread.join(timeout=join_timeout)
        if stderr_thread is not None:
            stderr_thread.join(timeout=join_timeout)
        return rc, "".join(stdout_chunks), "".join(stderr_chunks)

    deadline = (time.monotonic() + timeout) if timeout else None
    while True:
        try:
            rc = proc.wait(timeout=_POLL_INTERVAL_S)
        except subprocess.TimeoutExpired:
            if cancel_event is not None and cancel_event.is_set():
                logger.info("[!] Cancel requested — terminating %s", args[0])
                proc.terminate()
                try:
                    proc.wait(timeout=kill_grace_s)
                except subprocess.TimeoutExpired:
                    logger.warning("[!] %s did not exit after terminate — killing", args[0])
                    proc.kill()
                    proc.wait(timeout=2)
                return _finalize(CANCELLED_EXIT_CODE)
            if deadline is not None and time.monotonic() > deadline:
                proc.kill()
                proc.wait(timeout=2)
                _finalize(-1)
                raise ScannerTimeoutError(
                    f"{args[0]} exceeded timeout of {timeout}s"
                )
            continue
        return _finalize(rc)
