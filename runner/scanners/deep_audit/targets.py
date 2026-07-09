"""Candidate-file selection for the deep-audit engine.

Only files that look like route handlers reach the model — matched by path
keyword or by a route-registration marker in the content. Hard caps on file
count and size keep token cost (and wall-clock) bounded, mirroring the agent
scanner's approach.
"""
from __future__ import annotations

import os
from pathlib import Path

from runner.scanners.deep_audit.lenses.base import Lens

# Directories never worth auditing — vendored code, build output, VCS.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".venv",
    "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "target", "bin", "obj",
    "migrations", "test", "tests", "__tests__", "spec", "e2e", "fixtures",
})

# Source suffixes we can reason about. Binary/asset files are skipped.
_CODE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".java", ".kt", ".php",
    ".cs", ".rs", ".ex", ".exs",
})

_MAX_BYTES = 200_000  # a 200KB+ source file is generated/minified, not a handler


def select_files(
    repo_root: str, lens: Lens, *, max_files: int, max_chars: int,
) -> list[tuple[str, str]]:
    """Return up to ``max_files`` (relative_path, truncated_text) candidates for a
    lens. Path-keyword matches are preferred over content-only matches so the most
    likely handler files win the budget."""
    root = Path(repo_root)
    marker_re = lens.route_marker_re()
    by_path: list[tuple[str, str]] = []
    by_content: list[tuple[str, str]] = []

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            if Path(name).suffix not in _CODE_SUFFIXES:
                continue
            abs_path = Path(dirpath) / name
            try:
                if abs_path.stat().st_size > _MAX_BYTES:
                    continue
                text = abs_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = abs_path.relative_to(root).as_posix()
            excerpt = text[:max_chars]
            path_hit = any(k in rel.lower() for k in lens.path_keywords)
            if path_hit:
                by_path.append((rel, excerpt))
            elif marker_re.search(excerpt):
                by_content.append((rel, excerpt))

    return (by_path + by_content)[:max_files]
