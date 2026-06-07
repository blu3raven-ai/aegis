"""Tests for the refactored ManifestStreamer (batch presign, retry on expired URL)."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from runner.streamer import ManifestStreamer
from runner.uploader import URL_EXPIRED_MARKER


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _write_file(job_dir: Path, name: str, content: bytes) -> dict:
    (job_dir / name).parent.mkdir(parents=True, exist_ok=True)
    (job_dir / name).write_bytes(content)
    return {"file": name, "sha256": _sha(content)}


def _write_manifest(job_dir: Path, entries: list[dict]) -> None:
    (job_dir / "_manifest.jsonl").write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n"
    )


@pytest.fixture
def job_dir(tmp_path):
    return tmp_path


def test_streamer_calls_presign_once_per_poll_batch(job_dir):
    e1 = _write_file(job_dir, "a.json", b"a")
    e2 = _write_file(job_dir, "b.json", b"b")
    _write_manifest(job_dir, [e1, e2, {"file": "_done"}])

    backend = MagicMock()
    backend.presign_uploads.return_value = {
        "a.json": "https://minio/a",
        "b.json": "https://minio/b",
    }
    put_fn = MagicMock(return_value="ok")

    s = ManifestStreamer(
        job_dir=job_dir,
        backend_client=backend,
        put_fn=put_fn,
        job_id="job-1",
    )
    s.done_event.set()
    s.run()

    backend.presign_uploads.assert_called_once_with("job-1", ["a.json", "b.json"])
    assert put_fn.call_count == 2


def test_streamer_re_presigns_on_expired_url(job_dir):
    e1 = _write_file(job_dir, "a.json", b"a")
    _write_manifest(job_dir, [e1, {"file": "_done"}])

    backend = MagicMock()
    backend.presign_uploads.side_effect = [
        {"a.json": "https://minio/a-v1"},
        {"a.json": "https://minio/a-v2"},
    ]
    put_fn = MagicMock(side_effect=[URL_EXPIRED_MARKER, "ok"])

    s = ManifestStreamer(
        job_dir=job_dir,
        backend_client=backend,
        put_fn=put_fn,
        job_id="job-1",
    )
    s.done_event.set()
    s.run()

    assert backend.presign_uploads.call_count == 2
    assert put_fn.call_count == 2
    assert s.uploaded_count == 1


def test_streamer_handles_partial_backend_response(job_dir):
    e1 = _write_file(job_dir, "a.json", b"a")
    e2 = _write_file(job_dir, "b.json", b"b")
    e3 = _write_file(job_dir, "c.json", b"c")
    _write_manifest(job_dir, [e1, e2, e3, {"file": "_done"}])

    backend = MagicMock()
    backend.presign_uploads.return_value = {
        "a.json": "https://minio/a",
        "b.json": "https://minio/b",
    }
    put_fn = MagicMock(return_value="ok")

    s = ManifestStreamer(
        job_dir=job_dir,
        backend_client=backend,
        put_fn=put_fn,
        job_id="job-1",
    )
    s.done_event.set()
    s.run()

    assert s.uploaded_count == 2
    assert s.failed_count >= 1


def test_streamer_continues_when_backend_unreachable(job_dir):
    from runner.backend_client import BackendError
    e1 = _write_file(job_dir, "a.json", b"a")
    _write_manifest(job_dir, [e1, {"file": "_done"}])

    backend = MagicMock()
    backend.presign_uploads.side_effect = BackendError(0, "network down")
    put_fn = MagicMock(return_value="ok")

    s = ManifestStreamer(
        job_dir=job_dir,
        backend_client=backend,
        put_fn=put_fn,
        job_id="job-1",
    )
    s.done_event.set()
    s.run()
    assert s.failed_count >= 1
