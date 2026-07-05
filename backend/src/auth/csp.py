"""Compute SHA-256 hashes of static script files for CSP allow-listing.

This is the mechanism that eliminates `'unsafe-inline'` from script-src.
Called at FastAPI startup to read built Next.js chunks and produce hashes
matching what the browser will see at runtime.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path


def compute_inline_script_hashes(root: Path, pattern: str = "**/*.js") -> list[str]:
    """Return base64-encoded SHA-256 hashes of every file matching pattern under root.

    Deterministic: results are sorted by path for hash list stability. Default
    pattern is recursive (`**/*.js`) so Next.js chunks under `_next/static/chunks/`
    are picked up without callers having to know the layout.
    """
    hashes: list[str] = []
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).digest()
        hashes.append(base64.b64encode(digest).decode("ascii"))
    return hashes
