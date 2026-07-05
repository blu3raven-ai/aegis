"""Sandboxed read-only repo inspection tools: grep_repo, read_file_range."""
from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path

from argus.verification.tools.base import Tool


_MAX_FILE_BYTES = 1_000_000
_MAX_GREP_MATCHES = 20
_MAX_READ_LINES = 200
_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        "out",
        "coverage",
        "vendor",
        "target",
    }
)


@dataclasses.dataclass(frozen=True)
class _GrepMatch:
    file: str
    line: int
    snippet: str


def _resolve_inside_root(repo_root: Path, candidate: str) -> Path | None:
    """Resolve ``candidate`` relative to ``repo_root`` and reject escapes."""
    try:
        root = repo_root.resolve()
    except OSError:
        return None
    target = (root / candidate.lstrip("/")).resolve()
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


def _walk_files(repo_root: Path):
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in _EXCLUDED_DIRS and not d.startswith(".")]
        for name in filenames:
            yield Path(dirpath) / name


def grep_repo(repo_root: Path, pattern: str, max_matches: int = _MAX_GREP_MATCHES) -> list[_GrepMatch]:
    """Find regex matches inside the repo. Bounded, sandboxed, read-only."""
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid pattern: {exc}") from exc

    try:
        root = repo_root.resolve()
    except OSError:
        return []
    if not root.exists() or not root.is_dir():
        return []

    matches: list[_GrepMatch] = []
    for file_path in _walk_files(root):
        if len(matches) >= max_matches:
            break
        try:
            size = file_path.stat().st_size
        except OSError:
            continue
        if size == 0 or size > _MAX_FILE_BYTES:
            continue
        try:
            text = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if "\x00" in text[:1024]:
            continue
        rel = file_path.resolve().relative_to(root).as_posix()
        for line_no, line in enumerate(text.splitlines(), start=1):
            if regex.search(line):
                matches.append(_GrepMatch(file=rel, line=line_no, snippet=line.strip()[:200]))
                if len(matches) >= max_matches:
                    break

    return matches


def read_file_range(repo_root: Path, path: str, start: int, end: int) -> str:
    """Return lines [start, end] (1-indexed, inclusive) of ``path`` inside ``repo_root``."""
    if start < 1 or end < start:
        raise ValueError("invalid line range")
    if end - start + 1 > _MAX_READ_LINES:
        end = start + _MAX_READ_LINES - 1

    target = _resolve_inside_root(repo_root, path)
    if target is None:
        return f"// path '{path}' is outside the repo or symlinked out"
    if not target.exists() or not target.is_file():
        return f"// '{path}' not found"
    try:
        size = target.stat().st_size
    except OSError:
        return f"// '{path}' stat error"
    if size > _MAX_FILE_BYTES:
        return f"// '{path}' too large ({size} bytes)"
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return f"// '{path}' read error"
    lines = text.splitlines()
    s = max(0, start - 1)
    e = min(len(lines), end)
    return "\n".join(f"{i+1}: {lines[i]}" for i in range(s, e))


# ---------------------------------------------------------------------------
# Tool factories — bind the pure functions above to a specific repo_root
# ---------------------------------------------------------------------------


def make_grep_repo_tool(repo_root: Path) -> Tool:
    def handler(args: dict) -> str:
        pattern = args.get("pattern", "")
        if not pattern:
            return "// pattern is required"
        matches = grep_repo(repo_root, pattern)
        if not matches:
            return "// no matches"
        return "\n".join(f"{m.file}:{m.line}: {m.snippet}" for m in matches)

    return Tool(
        name="grep_repo",
        description=(
            "Search the user's repository for lines matching a Python regex. "
            "Returns up to 20 results as 'file:line: snippet'. Read-only."
        ),
        parameters={
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Python-style regex to search for.",
                }
            },
            "required": ["pattern"],
        },
        handler=handler,
    )


def make_read_file_range_tool(repo_root: Path) -> Tool:
    def handler(args: dict) -> str:
        path = args.get("path", "")
        start = int(args.get("start", 1))
        end = int(args.get("end", start + 39))
        if not path:
            return "// path is required"
        return read_file_range(repo_root, path, start, end)

    return Tool(
        name="read_file_range",
        description=(
            "Read a 1-indexed inclusive line range from a file in the user's repo. "
            "Capped at 200 lines per call. Read-only."
        ),
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Repo-relative path to the file.",
                },
                "start": {"type": "integer", "minimum": 1},
                "end": {"type": "integer", "minimum": 1},
            },
            "required": ["path", "start", "end"],
        },
        handler=handler,
    )
