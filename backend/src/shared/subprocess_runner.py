"""Shared subprocess execution helpers for scanner adapters.

Converts low-level subprocess failures into distinct exception types so
operators can triage problems quickly without digging through stack traces:

  AdapterUnavailableError  — binary not on PATH; install the tool.
  AdapterFailedError       — binary ran but returned a non-zero exit code.

The _try_incremental_* callers in each scanner already catch all exceptions and
fall through to the full-scan path, so these types are informational only —
they do not change the safe-fallback behaviour that was established in Phase 7.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Any


class AdapterUnavailableError(RuntimeError):
    """Raised when the scanner binary cannot be found on PATH."""


class AdapterFailedError(RuntimeError):
    """Raised when the scanner binary exits with a non-zero status."""

    def __init__(self, binary: str, returncode: int, stderr: str) -> None:
        super().__init__(f"{binary} exited {returncode}: {stderr[:500]}")
        self.returncode = returncode
        self.stderr = stderr


def run_subprocess(
    cmd: list[str],
    *,
    timeout: int = 300,
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run cmd, raising typed exceptions on failure.

    Parameters
    ----------
    cmd:
        Command + args list — first element is the binary name.
    timeout:
        Wall-clock seconds before the process is killed.
    **kwargs:
        Forwarded to subprocess.run (e.g. cwd, env).

    Returns
    -------
    subprocess.CompletedProcess with stdout captured as text.

    Raises
    ------
    AdapterUnavailableError
        When the binary is absent from PATH.
    AdapterFailedError
        When the process exits non-zero.
    """
    binary = cmd[0]
    if shutil.which(binary) is None:
        raise AdapterUnavailableError(
            f"{binary!r} not found on PATH — install the tool or add it to $PATH"
        )

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            **kwargs,
        )
    except FileNotFoundError:
        # Race between shutil.which and subprocess.run (rare but possible)
        raise AdapterUnavailableError(
            f"{binary!r} not found — may have been removed after PATH check"
        )

    if result.returncode != 0:
        raise AdapterFailedError(binary, result.returncode, result.stderr)

    return result
