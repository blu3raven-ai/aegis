"""Redis-backed job queue using Redis Streams.

One stream per scanner type: `<prefix><scanner_type>`. Each stream entry
holds a JSON-serialised job record. A Redis Hash index maps job_id to its
stream key and stream entry ID for O(1) get() lookups. A second Hash stores
a mutable status overlay so lifecycle updates (assign, start, complete, fail)
do not require rewriting immutable stream entries.

Consumer groups (`aegis-runners`) provide at-least-once delivery semantics
on assign_next. If a runner crashes before acknowledging, the entry stays in
the pending-entries list and can be reclaimed by a watchdog (future work).

Sensitive env vars are encrypted via src.runner.encryption for wire
compatibility with FileBackedQueue and PostgresBackedQueue.
"""
from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from typing import Any

import redis

from src.runner.encryption import encrypt_env_vars, decrypt_env_vars
from src.runner.queue._notify import publish_queued

_CONSUMER_GROUP = "aegis-runners"
# Scanner types iterated in assign_next priority order.
_SCANNER_TYPES = ("dependencies", "sast", "secrets", "containers")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_job_id() -> str:
    return f"job-{secrets.token_hex(8)}"


class RedisBackedQueue:
    """Job queue backed by Redis Streams.

    Parameters
    ----------
    redis_url:
        Redis connection URL. Falls back to REDIS_URL env var, then
        ``redis://localhost:6379/0``.
    stream_prefix:
        Prefix for all stream keys. Defaults to ``"aegis.jobs."``.
        Override in tests to isolate stream state between test runs.
    """

    def __init__(
        self,
        redis_url: str | None = None,
        stream_prefix: str = "aegis.jobs.",
    ) -> None:
        url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: redis.Redis = redis.Redis.from_url(url, decode_responses=False)
        self._prefix = stream_prefix
        # Hash: job_id -> "<stream_key>|<stream_entry_id>"
        self._index_key = f"{stream_prefix}_index"
        # Hash: job_id -> JSON overlay applied on top of base record
        self._status_key = f"{stream_prefix}_status"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _stream(self, job_type: str) -> str:
        return f"{self._prefix}{job_type}"

    def _ensure_group(self, stream: str) -> None:
        """Create the consumer group idempotently; swallow BUSYGROUP errors."""
        try:
            self._client.xgroup_create(stream, _CONSUMER_GROUP, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def _merge_overlay(self, job_id: str, fields: dict[str, Any]) -> None:
        """Merge *fields* into the status overlay for *job_id*."""
        raw = self._client.hget(self._status_key, job_id) or b"{}"
        existing: dict[str, Any] = json.loads(raw.decode())
        existing.update(fields)
        self._client.hset(self._status_key, job_id, json.dumps(existing))

    # ------------------------------------------------------------------
    # JobQueue Protocol
    # ------------------------------------------------------------------

    def create(
        self,
        *,
        job_type: str,
        org: str,
        run_id: str,
        docker_image: str,
        env_vars: dict[str, str],
    ) -> str:
        job_id = _make_job_id()
        record: dict[str, Any] = {
            "id": job_id,
            "jobType": job_type,
            "org": org,
            "runId": run_id,
            "status": "queued",
            "runnerId": None,
            "createdAt": _now_iso(),
            "startedAt": None,
            "completedAt": None,
            "dockerImage": docker_image,
            "envVars": encrypt_env_vars(env_vars),
        }
        stream = self._stream(job_type)
        # xadd returns bytes even without decode_responses=True
        entry_id = self._client.xadd(stream, {"job": json.dumps(record)}).decode()
        self._client.hset(self._index_key, job_id, f"{stream}|{entry_id}")
        publish_queued(job_type, job_id)
        return job_id

    def get(self, job_id: str) -> dict[str, Any] | None:
        location = self._client.hget(self._index_key, job_id)
        if not location:
            return None
        stream, entry_id = location.decode().split("|", 1)
        entries = self._client.xrange(stream, min=entry_id, max=entry_id, count=1)
        if not entries:
            return None
        _, fields = entries[0]
        record: dict[str, Any] = json.loads(fields[b"job"].decode())
        # Apply mutable status overlay (status, runnerId, result, error, etc.)
        overlay_raw = self._client.hget(self._status_key, job_id)
        if overlay_raw:
            record.update(json.loads(overlay_raw.decode()))
        # Always decrypt for the public API
        record["envVars"] = decrypt_env_vars(record["envVars"])
        return record

    def _active_streams(self) -> list[str]:
        """Return all Redis Stream keys that exist under the queue prefix.

        Uses SCAN + TYPE to exclude the Hash meta-keys (_index, _status)
        that share the same prefix. Priority streams (known scanner types)
        are listed first; ad-hoc job_types follow in sorted order.
        """
        pattern = f"{self._prefix}*".encode()
        cursor = 0
        found: set[str] = set()
        while True:
            cursor, keys = self._client.scan(cursor=cursor, match=pattern, count=100)
            for k in keys:
                key_str = k.decode()
                if self._client.type(k) == b"stream":
                    found.add(key_str)
            if cursor == 0:
                break
        # Priority order: known types first, then any extras sorted for stability
        priority = [self._stream(t) for t in _SCANNER_TYPES]
        ordered = [s for s in priority if s in found]
        extras = sorted(found - set(priority))
        return ordered + extras

    def assign_next(self, runner_id: str) -> dict[str, Any] | None:
        """Pull the next queued job across all active streams.

        Iterates known scanner types first (in priority order), then any
        additional streams that exist under the prefix. Returns the first
        job found, or None if all streams are empty.
        """
        for stream in self._active_streams():
            self._ensure_group(stream)
            # block=100ms so we don't spin-burn CPU when the stream is empty
            response = self._client.xreadgroup(
                _CONSUMER_GROUP, runner_id, {stream: ">"}, count=1, block=100,
            )
            if not response:
                continue
            for _stream_key, entries in response:
                for _entry_id, entry_fields in entries:
                    record: dict[str, Any] = json.loads(entry_fields[b"job"].decode())
                    overlay = {
                        "status": "assigned",
                        "runnerId": runner_id,
                        "startedAt": _now_iso(),
                    }
                    self._merge_overlay(record["id"], overlay)
                    record.update(overlay)
                    record["envVars"] = decrypt_env_vars(record["envVars"])
                    return record
        return None

    def mark_started(self, job_id: str) -> None:
        self._merge_overlay(job_id, {"status": "running"})

    def mark_completed(self, job_id: str, result: dict[str, Any] | None = None) -> None:
        overlay: dict[str, Any] = {"status": "completed", "completedAt": _now_iso()}
        if result is not None:
            overlay["result"] = result
        self._merge_overlay(job_id, overlay)

    def mark_failed(self, job_id: str, error: str, *, retryable: bool = False) -> None:
        self._merge_overlay(job_id, {
            "status": "queued" if retryable else "failed",
            "error": error,
        })
