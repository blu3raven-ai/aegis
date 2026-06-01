"""Port of scanners/shared/lib.sh — helpers shared by every scanner module.

Stdout progress markers MUST match the exact strings emitted by the bash
originals so the runner's ManifestStreamer regex parser continues to work."""
from __future__ import annotations

import logging
import os
import subprocess
import threading
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

from runner.scanners import _manifest

logger = logging.getLogger(__name__)


class InsecureURLError(ValueError):
    """Raised when a non-HTTPS git URL is passed to clone_repo."""


class GitCloneError(RuntimeError):
    """Raised when git clone fails. Token is scrubbed from any captured output."""


def setup_output_dir(job_id: str, base_dir: Path | str = "/workspace") -> Path:
    """Create and return /<base_dir>/<job_id>/. Idempotent."""
    out = Path(base_dir) / job_id
    out.mkdir(parents=True, exist_ok=True)
    return out


def repo_name_from_url(url: str) -> str:
    """Extract the basename from a git URL, stripping .git and trailing /."""
    path = url.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    path = path.rstrip("/")
    return path.rsplit("/", 1)[-1]


def parse_repos(input_str: str) -> list[str]:
    """Accept comma- or newline-separated repos, or a path to a file with one per line."""
    if not input_str:
        return []
    looks_like_path = (
        len(input_str) < 4096
        and "\n" not in input_str
        and "," not in input_str
    )
    if looks_like_path:
        try:
            candidate = Path(input_str)
            raw = candidate.read_text() if candidate.is_file() else input_str
        except (OSError, ValueError):
            raw = input_str
    else:
        raw = input_str
    return [line.strip() for line in raw.replace(",", "\n").splitlines() if line.strip()]


def clone_repo(
    url: str,
    dest: Path | str,
    *,
    token: str | None = None,
    depth: int | None = 1,
    timeout: float = 300.0,
) -> None:
    """Clone a git repo. HTTPS-only; injects token via URL rewrite if provided.

    ``depth=None`` performs a full-history clone (no ``--depth`` / no
    ``--single-branch``) — required by the secrets scanner's ``deep`` and
    ``ai_enhanced`` modes which must walk every commit.
    """
    if not url.startswith("https://"):
        raise InsecureURLError(f"Refused non-HTTPS git URL: {url}")

    parts = urlsplit(url)
    if "@" in parts.netloc:
        raise InsecureURLError(f"Refused git URL containing embedded user-info: {url}")

    if token:
        netloc_with_auth = f"x-access-token:{token}@{parts.netloc}"
        auth_url = urlunsplit(
            (parts.scheme, netloc_with_auth, parts.path, parts.query, parts.fragment)
        )
    else:
        auth_url = url

    cmd = ["git", "clone"]
    if depth is not None:
        cmd.extend(["--depth", str(depth), "--single-branch"])
    cmd.extend([auth_url, str(dest)])
    try:
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        stderr_clean = (e.stderr or "")
        if token:
            stderr_clean = stderr_clean.replace(auth_url, url)
        raise GitCloneError(
            f"git clone failed for {url}: rc={e.returncode}: {stderr_clean.strip()[:500]}"
        ) from None
    except subprocess.TimeoutExpired:
        raise GitCloneError(f"git clone timed out for {url} after {timeout}s") from None


def register_output(output_dir: Path, file_path: Path, repo: str) -> None:
    """Append a sha256 manifest entry for a per-repo output file."""
    _manifest.record_output(output_dir, file_path, repo)


def log_scanning(target: str) -> None:
    print(f"[+] Scanning repo: {target}", flush=True)


def log_scanning_image(target: str) -> None:
    print(f"[+] Scanning image: {target}", flush=True)


def log_finished(target: str) -> None:
    print(f"[✓] Finished: {target}", flush=True)


class ProgressEmitter:
    """Thread-safe wrapper around the agent's ``on_progress`` callback.

    Tracks monotonic counters (scanned, finished) and emits the dict shape the
    backend expects. Safe to call from multiple threads (ThreadPoolExecutor).

    The agent merges its own streamer counters into the dict server-side, so
    this emitter intentionally does not track uploaded/failed counts.
    """

    _LOG_TAIL_MAX = 50

    def __init__(
        self,
        on_progress: Callable[[list[str], dict], None] | None,
        expected: int,
    ) -> None:
        self._on_progress = on_progress
        self._lock = threading.Lock()
        self._scanned = 0
        self._finished = 0
        self._expected = max(0, int(expected))
        self._stage = "starting"
        self._current_repo: str | None = None
        self._log_tail: list[str] = []

    def starting(self) -> None:
        with self._lock:
            self._stage = "starting"
            self._emit_locked()

    def scanning(self, repo: str) -> None:
        with self._lock:
            self._scanned += 1
            self._current_repo = repo
            self._stage = "scanning"
            self._emit_locked()

    def finished(self, repo: str) -> None:
        with self._lock:
            self._finished += 1
            if self._current_repo == repo:
                self._current_repo = None
            self._emit_locked()

    def normalizing(self) -> None:
        with self._lock:
            self._stage = "normalizing"
            self._current_repo = None
            self._emit_locked()

    def done(self) -> None:
        with self._lock:
            self._finished = self._expected
            self._stage = "done"
            self._current_repo = None
            self._emit_locked()

    def log(self, line: str) -> None:
        with self._lock:
            self._log_tail.append(line)
            if len(self._log_tail) > self._LOG_TAIL_MAX:
                self._log_tail = self._log_tail[-self._LOG_TAIL_MAX :]

    def _emit_locked(self) -> None:
        if self._on_progress is None:
            return
        progress: dict = {
            "scannedRepos": self._scanned,
            "finishedRepos": self._finished,
            "expectedRepos": self._expected,
            "stage": self._stage,
        }
        if self._current_repo:
            progress["currentRepo"] = self._current_repo
        try:
            self._on_progress(list(self._log_tail), progress)
        except Exception:  # noqa: BLE001
            # A failed progress emission must never abort the scan.
            logger.debug("on_progress callback raised; ignoring", exc_info=True)
