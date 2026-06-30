"""Grep-verify every evidence citation against the actual repo."""
from __future__ import annotations

from pathlib import Path


def verify_citations(evidence: list[dict], repo_root: str) -> tuple[list[str], list[str]]:
    """Return (unverified_citations, ungrounded_tokens).

    file:line citations must match within ±2 lines. ``kind="advisory"`` skips
    the file check but still requires ``source`` + non-empty ``snippet``.
    """
    unverified: list[str] = []
    for item in evidence:
        kind = (item.get("kind") or "").strip()
        snippet = (item.get("snippet") or "").strip()

        if kind == "advisory":
            source = (item.get("source") or "").strip()
            if not source or not snippet:
                unverified.append(f"advisory:{source or '?'} (missing_source_or_snippet)")
            continue

        f = item.get("file", "")
        line = int(item.get("line", 0) or 0)
        if not f or not snippet:
            unverified.append(f"{f}:{line}")
            continue

        path = Path(repo_root) / f
        if not path.exists():
            unverified.append(f"{f}:{line} (file_missing)")
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            unverified.append(f"{f}:{line} (read_error)")
            continue

        lines = text.splitlines()
        start = max(0, line - 3)
        end = min(len(lines), line + 2)
        window = "\n".join(lines[start:end])
        if snippet not in window:
            unverified.append(f"{f}:{line} (snippet_not_found)")

    return unverified, []
