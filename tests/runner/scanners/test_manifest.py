"""Tests for manifest writer — _manifest.jsonl format must match scanners/shared/manifest.py exactly."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from runner.scanners._manifest import record_output, write_done_marker, sha256_file


def test_sha256_file_matches_hashlib(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello world")
    assert sha256_file(p) == hashlib.sha256(b"hello world").hexdigest()


def test_record_output_appends_jsonl_entry(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = out_dir / "report.json"
    target.write_text('{"x": 1}')

    record_output(out_dir, target, repo="acme/widget")

    manifest = (out_dir / "_manifest.jsonl").read_text().splitlines()
    assert len(manifest) == 1
    entry = json.loads(manifest[0])
    assert entry["file"] == "report.json"
    assert entry["repo"] == "acme/widget"
    assert entry["sha256"] == hashlib.sha256(b'{"x": 1}').hexdigest()
    assert "ts" in entry


def test_record_output_skips_empty_file(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    target = out_dir / "empty.json"
    target.write_text("")

    record_output(out_dir, target, repo="acme/widget")

    assert not (out_dir / "_manifest.jsonl").exists()


def test_record_output_skips_traversal_paths(tmp_path):
    """Path outside output dir → no entry written (existing security guard)."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    other = tmp_path / "other.json"
    other.write_text('{"y": 2}')

    record_output(out_dir, other, repo="acme/widget")

    assert not (out_dir / "_manifest.jsonl").exists()


def test_record_output_thread_safe(tmp_path):
    """Concurrent writes from many threads should produce well-formed JSONL — no torn lines."""
    import threading

    out_dir = tmp_path / "out"
    out_dir.mkdir()

    def worker(i):
        f = out_dir / f"f{i}.json"
        f.write_text('{"id": ' + str(i) + '}' * 100)
        record_output(out_dir, f, repo=f"repo-{i}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = (out_dir / "_manifest.jsonl").read_text().splitlines()
    assert len(lines) == 20
    for line in lines:
        json.loads(line)


def test_write_done_marker_appends_done_entry(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    findings = out_dir / "findings.jsonl"
    findings.write_text('{"id": 1}\n')

    write_done_marker(out_dir)

    lines = (out_dir / "_manifest.jsonl").read_text().splitlines()
    assert len(lines) == 2
    findings_entry = json.loads(lines[0])
    done_entry = json.loads(lines[1])
    assert findings_entry["file"] == "findings.jsonl"
    assert findings_entry["repo"] == "_all"
    assert done_entry["file"] == "_done"
    assert done_entry["totalFiles"] == 1
