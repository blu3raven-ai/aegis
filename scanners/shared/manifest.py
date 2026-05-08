#!/usr/bin/env python3
"""Records output files with sha256 checksums in _manifest.jsonl."""
import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def record_output(output_dir: str, file_path: str, repo: str) -> None:
    """Append a per-repo output file entry to the manifest."""
    if not os.path.exists(file_path) or not os.path.getsize(file_path):
        return

    manifest_path = os.path.join(output_dir, "_manifest.jsonl")
    relative = os.path.relpath(file_path, output_dir)

    if relative.startswith(".."):
        return

    sha256 = _sha256_file(file_path)
    entry = {
        "file": relative,
        "repo": repo,
        "ts": datetime.now(timezone.utc).isoformat(),
        "sha256": sha256,
    }
    with open(manifest_path, "a") as f:
        f.write(json.dumps(entry) + "\n")
        f.flush()
        os.fsync(f.fileno())


def main() -> None:
    output_dir = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("OUTDIR", "/scanner/output")
    findings_path = os.path.join(output_dir, "findings.jsonl")
    manifest_path = os.path.join(output_dir, "_manifest.jsonl")

    count = 0
    if os.path.exists(findings_path):
        # Fsync to guarantee write ordering before manifest entry
        fd = os.open(findings_path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

        sha256 = _sha256_file(findings_path)
        entry = {
            "file": "findings.jsonl",
            "repo": "_all",
            "ts": datetime.now(timezone.utc).isoformat(),
            "sha256": sha256,
        }
        with open(manifest_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())
        count = 1
        logger.info("[+] Manifest: recorded findings.jsonl (sha256=%s...)", sha256[:12])

    done = {
        "file": "_done",
        "ts": datetime.now(timezone.utc).isoformat(),
        "totalFiles": count,
    }
    with open(manifest_path, "a") as f:
        f.write(json.dumps(done) + "\n")
        f.flush()
        os.fsync(f.fileno())

    logger.info("[+] Manifest: _done (%d file(s))", count)


if __name__ == "__main__":
    main()
