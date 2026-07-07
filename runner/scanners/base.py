"""Shared ExecutionResult returned by every embedded scanner module."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExecutionResult:
    exit_code: int | None
    job_dir: Path
    log_tail: list[str] = field(default_factory=list)
