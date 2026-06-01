"""BaseScanner protocol and ExecutionResult for embedded scanner modules."""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Protocol, runtime_checkable


@dataclass
class ExecutionResult:
    exit_code: int | None
    job_dir: Path
    log_tail: list[str] = field(default_factory=list)


@runtime_checkable
class BaseScanner(Protocol):
    SCANNER_TYPE: str

    def run_scan(
        self,
        job: dict,
        job_dir: Path,
        on_progress: Callable[[list[str], dict], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> ExecutionResult: ...
