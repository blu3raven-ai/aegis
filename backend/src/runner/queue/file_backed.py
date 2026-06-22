"""File-backed job queue implementation.

Refactored from the original module-level functions in jobs.py — same
semantics, now behind the JobQueue Protocol. The original jobs.py
re-exports these for backward compat (see jobs.py edit in Task 14).

Encryption note: env-var encryption replicates jobs.py exactly (ENC: prefix,
PBKDF2-derived Fernet key from RUNNER_ENCRYPTION_KEY) so job records produced here
are wire-compatible with records produced by the original jobs.py functions.
"""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path
from threading import Lock
from typing import Any

from src.runner.encryption import encrypt_env_vars, decrypt_env_vars
from src.shared.paths import now_iso

_DEFAULT_DIR = Path(os.environ.get("DATA_DIR", "/var/lib/aegis")) / "jobs"

# Cipher helpers from the shared module — see src/runner/encryption.py.
_encrypt_env_vars = encrypt_env_vars
_decrypt_env_vars = decrypt_env_vars


class FileBackedQueue:
    """Job queue backed by one JSON file per job in a local directory.

    Thread-safe for concurrent assign_next calls via an in-process lock.
    Not safe across multiple processes — use PostgresBackedQueue for that.
    """

    def __init__(self, storage_dir: Path | None = None) -> None:
        self._dir = storage_dir or _DEFAULT_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._assign_lock = Lock()

    def _path(self, job_id: str) -> Path:
        return self._dir / f"{job_id}.json"

    def _read(self, path: Path) -> dict[str, Any]:
        return json.loads(path.read_text())

    def _write(self, path: Path, record: dict[str, Any]) -> None:
        path.write_text(json.dumps(record))

    def create(
        self,
        *,
        job_type: str,
        org: str,
        run_id: str,
        env_vars: dict[str, str],
    ) -> str:
        job_id = f"job-{secrets.token_hex(8)}"
        record: dict[str, Any] = {
            "id": job_id,
            "jobType": job_type,
            "org": org,
            "runId": run_id,
            "status": "queued",
            "runnerId": None,
            "createdAt": now_iso(),
            "startedAt": None,
            "completedAt": None,
            "envVars": _encrypt_env_vars(env_vars),
        }
        self._write(self._path(job_id), record)
        return job_id

    def assign_next(self, runner_id: str) -> dict[str, Any] | None:
        with self._assign_lock:
            candidates = sorted(
                (p for p in self._dir.glob("*.json")),
                key=lambda p: self._read(p).get("createdAt", ""),
            )
            for path in candidates:
                record = self._read(path)
                if record.get("status") == "queued":
                    record["status"] = "assigned"
                    record["runnerId"] = runner_id
                    record["startedAt"] = now_iso()
                    self._write(path, record)
                    record["envVars"] = _decrypt_env_vars(record["envVars"])
                    return record
        return None

    def mark_started(self, job_id: str) -> None:
        path = self._path(job_id)
        record = self._read(path)
        record["status"] = "running"
        self._write(path, record)

    def mark_completed(self, job_id: str, result: dict[str, Any] | None = None) -> None:
        path = self._path(job_id)
        record = self._read(path)
        record["status"] = "completed"
        record["completedAt"] = now_iso()
        if result is not None:
            record["result"] = result
        self._write(path, record)

    def mark_failed(self, job_id: str, error: str, *, retryable: bool = False) -> None:
        path = self._path(job_id)
        record = self._read(path)
        record["status"] = "queued" if retryable else "failed"
        record["error"] = error
        self._write(path, record)

    def get(self, job_id: str) -> dict[str, Any] | None:
        path = self._path(job_id)
        if not path.exists():
            return None
        record = self._read(path)
        record["envVars"] = _decrypt_env_vars(record["envVars"])
        return record
