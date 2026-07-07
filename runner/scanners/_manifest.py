"""Append sha256-checksummed entries to _manifest.jsonl.

Port of scanners/shared/manifest.py — same byte-level format so the runner's
ManifestStreamer (runner/streamer.py) continues to work without changes."""
from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path


_manifest_locks: dict[str, threading.Lock] = {}
_locks_lock = threading.Lock()


def _get_lock(output_dir: Path) -> threading.Lock:
    key = str(output_dir.resolve())
    with _locks_lock:
        if key not in _manifest_locks:
            _manifest_locks[key] = threading.Lock()
        return _manifest_locks[key]


def sha256_file(path: Path) -> str:
    """Compute sha256 without loading the whole file into memory."""
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fsync_append(path: Path, payload: str) -> None:
    lock = _get_lock(path.parent)
    with lock:
        with open(path, "a") as f:
            f.write(payload + "\n")
            f.flush()
            os.fsync(f.fileno())


def record_output(output_dir: Path, file_path: Path, repo: str) -> None:
    """Append a per-repo output file entry to _manifest.jsonl.

    Skips: missing files, empty files, paths outside output_dir (traversal guard)."""
    if not file_path.exists() or file_path.stat().st_size == 0:
        return

    try:
        relative = file_path.resolve().relative_to(output_dir.resolve())
    except ValueError:
        return

    entry = {
        "file": str(relative),
        "repo": repo,
        "ts": _now_iso(),
        "sha256": sha256_file(file_path),
    }
    _fsync_append(output_dir / "_manifest.jsonl", json.dumps(entry))


def write_done_marker(output_dir: Path) -> None:
    """Record findings.jsonl (if present) and append the _done marker.

    Mirrors the main() of scanners/shared/manifest.py."""
    findings = output_dir / "findings.jsonl"
    count = 0
    if findings.exists():
        fd = os.open(findings, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

        entry = {
            "file": "findings.jsonl",
            "repo": "_all",
            "ts": _now_iso(),
            "sha256": sha256_file(findings),
        }
        _fsync_append(output_dir / "_manifest.jsonl", json.dumps(entry))
        count = 1

    done = {"file": "_done", "ts": _now_iso(), "totalFiles": count}
    _fsync_append(output_dir / "_manifest.jsonl", json.dumps(done))
