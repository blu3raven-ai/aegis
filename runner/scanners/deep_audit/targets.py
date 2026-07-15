"""Candidate route-handler selection for the authz audit.

Only files that look like route handlers reach the model — matched by a path
keyword or a route-registration marker in the content — with hard caps on file
count and size so token cost stays bounded. This is the *recall* step: semgrep
can enumerate handlers, but only an LLM can reason about whether each one
enforces authorization, so a lightweight enumerator feeds the reasoning turn.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "vendor", "dist", "build", "out", ".next", ".venv",
    "venv", "__pycache__", ".mypy_cache", ".pytest_cache", "target", "bin", "obj",
    "migrations", "test", "tests", "__tests__", "spec", "e2e", "fixtures",
})

_CODE_SUFFIXES = frozenset({
    ".py", ".js", ".jsx", ".ts", ".tsx", ".rb", ".go", ".java", ".kt", ".php",
    ".cs", ".rs", ".ex", ".exs",
})

_MAX_BYTES = 200_000  # a 200KB+ source file is generated/minified, not a handler

# Path fragments and in-file markers that identify HTTP route handlers across the
# common frameworks. Hardcoded (authz is the only audit class); generalise to a
# registry only when a second class actually needs different markers.
_PATH_KEYWORDS = (
    "route", "router", "controller", "handler", "endpoint", "/api/", "/views",
    "urls.py", "routes.rb", "/resolvers",
)
_ROUTE_MARKERS = (
    "@app.", "@router.", "app.get(", "app.post(", "app.put(", "app.delete(",
    "router.get(", "router.post(", "@RestController", "@GetMapping", "@PostMapping",
    "@RequestMapping", "def create", "def update", "def destroy", "path(", "resources ",
    "@strawberry.field", "@Get(", "@Post(", "http.HandleFunc",
)
_MARKER_RE = re.compile("|".join(re.escape(m) for m in _ROUTE_MARKERS))


def select_files(repo_root: str, *, max_files: int, max_chars: int) -> list[tuple[str, str]]:
    """Return up to ``max_files`` ``(relative_path, truncated_text)`` handler
    candidates. Path-keyword matches are preferred over content-only matches so the
    most likely handler files win the budget."""
    root = Path(repo_root)
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
            if any(k in rel.lower() for k in _PATH_KEYWORDS):
                by_path.append((rel, excerpt))
            elif _MARKER_RE.search(excerpt):
                by_content.append((rel, excerpt))

    return (by_path + by_content)[:max_files]
