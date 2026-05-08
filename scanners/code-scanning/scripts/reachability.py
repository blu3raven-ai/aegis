#!/usr/bin/env python3
"""reachability.py — tree-sitter call graph reachability for SAST findings.

Usage:
    python3 reachability.py <clone_dir> <sarif_file> <output_file>

Writes a JSON object keyed by "file_path:start_line" with:
  { "verdict": "reachable"|"unreachable"|"unknown",
    "entry_point": str,           # only when reachable
    "call_chain": [               # only when reachable
      {"function": str, "file": str, "line": int}, ...
    ]
  }
"""
from __future__ import annotations

import json
import logging
import re
import sys
import warnings

logger = logging.getLogger(__name__)
from collections import deque

# tree-sitter internals emit a FutureWarning on older grammar packages
warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")
from pathlib import Path
from typing import Any

# ── tree-sitter import (graceful fallback if not installed) ──────────────

try:
    from tree_sitter_languages import get_parser as _ts_get_parser

    def _get_parser(lang: str):
        try:
            return _ts_get_parser(lang)
        except Exception:
            return None

except ImportError:
    def _get_parser(lang: str):
        return None

# ── Language map ─────────────────────────────────────────────────────────

EXTENSION_TO_LANG: dict[str, str] = {
    ".py":  "python",
    ".js":  "javascript",
    ".jsx": "javascript",
    ".ts":  "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go":  "go",
    ".rb":  "ruby",
    ".php": "php",
    ".c":   "c",
    ".cpp": "cpp",
    ".cc":  "cpp",
    ".cs":  "c_sharp",
}

# ── AST node type sets ────────────────────────────────────────────────────

FUNC_DEF_TYPES = frozenset({
    "function_definition",    # Python, PHP
    "function_declaration",   # JS, TS, C, C++
    "method_declaration",     # Java, C#, PHP
    "func_declaration",       # Go
    "method_definition",      # JS class bodies
    "method",                 # Ruby
})

CALL_TYPES = frozenset({
    "call",                       # Python, Ruby
    "call_expression",            # JS, TS, Go, C, C++
    "method_invocation",          # Java
    "invocation_expression",      # C#
    "function_call_expression",   # PHP
    "method_call_expression",     # PHP
})

# ── Entry point patterns ──────────────────────────────────────────────────

ENTRY_PATH_RE = re.compile(
    r"/(routes?|handlers?|controllers?|views?|endpoints?|api|cmd|app)/",
    re.IGNORECASE,
)
ENTRY_FILE_RE = re.compile(
    r"^(app|main|server|index|cli|entrypoint)\.[a-z]+$",
    re.IGNORECASE,
)
ENTRY_DECORATOR_RE = re.compile(
    r"@(app|router|blueprint|api|bp)\.(route|get|post|put|delete|patch|head|options)",
    re.IGNORECASE,
)
ENTRY_ANNOTATION_RE = re.compile(
    r"@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|"
    r"WebServlet|EventHandler|MessageHandler)\b"
)
ENTRY_FUNC_NAMES = frozenset({
    "main", "Main", "run", "Run", "start", "Start",
    "serve", "Serve", "handler", "Handle", "index",
})

SKIP_DIRS = frozenset({
    "node_modules", ".git", "vendor", "dist", "build",
    "__pycache__", ".tox", "venv", ".venv",
})

# Directories that strongly suggest dead / non-production code.
# A finding whose file path passes through one of these segments is
# considered unreachable even when it lives at module level.
DEAD_CODE_DIRS = frozenset({
    "archived", "archive", "deprecated", "legacy",
    "unused", "trash", "scratch", "old",
    "test", "tests", "spec", "specs",
    "benchmark", "benchmarks", "fixtures",
    "examples", "sample", "samples", "demo",
})

# ── AST helpers ──────────────────────────────────────────────────────────


def _get_name(node) -> str | None:
    """Get a function's name from its definition node."""
    name_node = node.child_by_field_name("name")
    if name_node:
        return name_node.text.decode("utf-8", errors="replace")
    # C / C++: declarator → find nested identifier
    decl = node.child_by_field_name("declarator")
    if decl:
        found = _find_type(decl, "identifier")
        if found:
            return found.text.decode("utf-8", errors="replace")
    return None


def _find_type(node, typ: str):
    """Depth-first search for first node with given type."""
    if node.type == typ:
        return node
    for child in node.children:
        result = _find_type(child, typ)
        if result:
            return result
    return None


def _get_callee(node) -> str | None:
    """Extract the simple callee name from a call node."""
    func = (
        node.child_by_field_name("function")
        or node.child_by_field_name("method")
        or node.child_by_field_name("name")
    )
    if not func:
        return None
    if func.type == "identifier":
        return func.text.decode("utf-8", errors="replace")
    # member_expression / attribute / selector_expression — rightmost identifier
    for field in ("attribute", "property", "field"):
        attr = func.child_by_field_name(field)
        if attr and attr.type == "identifier":
            return attr.text.decode("utf-8", errors="replace")
    # Fallback: last identifier child
    last = None
    for child in func.children:
        if child.type == "identifier":
            last = child
    return last.text.decode("utf-8", errors="replace") if last else None


# ── Per-file extraction ──────────────────────────────────────────────────


def _collect_calls(node) -> list[str]:
    """Collect all callee names within a node (non-recursive into nested defs)."""
    calls: list[str] = []

    def walk(n):
        if n.type in CALL_TYPES:
            callee = _get_callee(n)
            if callee:
                calls.append(callee)
        for child in n.children:
            # Don't recurse into nested function bodies
            if child.type not in FUNC_DEF_TYPES:
                walk(child)

    walk(node)
    return list(set(calls))


def _extract_functions(root_node, rel_path: str) -> list[dict]:
    """Walk AST root and return all function definitions."""
    filename = Path(rel_path).name
    file_is_entry = bool(
        ENTRY_PATH_RE.search(rel_path) or ENTRY_FILE_RE.match(filename)
    )

    functions: list[dict] = []

    def walk(node, decorator_text: str = ""):
        # Python decorated_definition wraps decorator + function
        if node.type == "decorated_definition":
            deco_parts = []
            inner_func = None
            for child in node.children:
                if child.type == "decorator":
                    deco_parts.append(child.text.decode("utf-8", errors="replace"))
                elif child.type in FUNC_DEF_TYPES:
                    inner_func = child
            combined = "\n".join(deco_parts)
            if inner_func is not None:
                walk(inner_func, decorator_text=combined)
            return

        if node.type in FUNC_DEF_TYPES:
            name = _get_name(node)
            if name is None:
                for child in node.children:
                    walk(child)
                return

            is_entry = (
                file_is_entry
                or name in ENTRY_FUNC_NAMES
                or bool(ENTRY_DECORATOR_RE.search(decorator_text))
                or bool(ENTRY_ANNOTATION_RE.search(decorator_text))
            )

            functions.append({
                "name": name,
                "file": rel_path,
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "calls": _collect_calls(node),
                "is_entry": is_entry,
            })
            # Don't walk into nested functions at this level
            return

        for child in node.children:
            walk(child)

    walk(root_node)
    return functions


def parse_file(abs_path: Path, rel_path: str) -> list[dict]:
    """Parse a source file; return [] on any error."""
    lang = EXTENSION_TO_LANG.get(abs_path.suffix.lower())
    if not lang:
        return []
    parser = _get_parser(lang)
    if parser is None:
        return []
    try:
        source = abs_path.read_bytes()
        tree = parser.parse(source)
        return _extract_functions(tree.root_node, rel_path)
    except Exception:
        return []


# ── Call graph ────────────────────────────────────────────────────────────


class CallGraph:
    def __init__(self) -> None:
        self._by_name: dict[str, list[dict]] = {}
        self._all: list[dict] = []
        self.entry_points: list[dict] = []

    def add(self, fn: dict) -> None:
        name = fn["name"]
        self._by_name.setdefault(name, []).append(fn)
        self._all.append(fn)
        if fn["is_entry"]:
            self.entry_points.append(fn)

    def containing_function(self, file: str, line: int) -> dict | None:
        """Smallest function definition containing (file, line)."""
        candidates = [
            fn for fn in self._all
            if fn["file"] == file
            and fn["start_line"] <= line <= fn["end_line"]
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda f: f["end_line"] - f["start_line"])

    def callees(self, fn: dict) -> list[dict]:
        result = []
        for name in fn.get("calls", []):
            result.extend(self._by_name.get(name, []))
        return result

    def bfs_to(self, target: dict) -> list[dict] | None:
        """BFS from all entry points; return shortest path to target or None."""
        t_key = (target["file"], target["start_line"])

        if target.get("is_entry"):
            return [target]

        visited: set[tuple[str, int]] = set()
        queue: deque[tuple[dict, list[dict]]] = deque()

        for ep in self.entry_points:
            k = (ep["file"], ep["start_line"])
            if k not in visited:
                visited.add(k)
                queue.append((ep, [ep]))

        while queue:
            fn, path = queue.popleft()
            for callee in self.callees(fn):
                k = (callee["file"], callee["start_line"])
                if k == t_key:
                    return path + [callee]
                if k not in visited:
                    visited.add(k)
                    queue.append((callee, path + [callee]))

        return None


# ── Main ─────────────────────────────────────────────────────────────────


def build_reachability(clone_dir: str, sarif_file: str) -> dict[str, Any]:
    clone_path = Path(clone_dir)
    sarif_path = Path(sarif_file)

    if not sarif_path.exists():
        return {}

    try:
        sarif = json.loads(sarif_path.read_bytes())
    except Exception:
        return {}

    # Collect unique (file, line) pairs from SARIF findings
    finding_locs: list[dict] = []
    seen: set[str] = set()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "")
            line = phys.get("region", {}).get("startLine", 0)
            key = f"{uri}:{line}"
            if uri and line and key not in seen:
                seen.add(key)
                finding_locs.append({"file": uri, "line": line})

    if not finding_locs:
        return {}

    # Build call graph from all source files
    graph = CallGraph()
    for abs_path in clone_path.rglob("*"):
        if not abs_path.is_file():
            continue
        # Skip irrelevant directories
        if any(part in SKIP_DIRS for part in abs_path.parts):
            continue
        rel = str(abs_path.relative_to(clone_path))
        for fn in parse_file(abs_path, rel):
            graph.add(fn)

    # Pre-compute clone prefix for path normalisation.
    # Opengrep writes absolute paths (/tmp/tmp.XXXX/server.py) into the SARIF
    # but the call graph stores relative paths (server.py).  Strip the prefix
    # before lookup while keeping the original URI as the output key so it
    # matches the $ctx_key used by normalize-code-scanning.sh.
    clone_prefix = str(clone_path).rstrip("/") + "/"

    output: dict[str, Any] = {}

    for loc in finding_locs:
        key = f"{loc['file']}:{loc['line']}"

        rel_file = loc["file"]
        if rel_file.startswith(clone_prefix):
            rel_file = rel_file[len(clone_prefix):]

        containing = graph.containing_function(rel_file, loc["line"])
        if containing is None:
            # Module-level code: the finding sits outside any function.
            # If the file's path passes through a known dead-code directory,
            # treat it as unreachable; otherwise it is always executed on
            # import so treat it as reachable (module-level exposure).
            path_parts = frozenset(Path(rel_file).parts[:-1])  # exclude filename
            if path_parts & DEAD_CODE_DIRS:
                output[key] = {"verdict": "unreachable"}
            else:
                output[key] = {"verdict": "reachable", "entry_point": "module-level"}
            continue

        if not graph.entry_points:
            output[key] = {"verdict": "unknown"}
            continue

        path = graph.bfs_to(containing)
        if path is None:
            output[key] = {"verdict": "unreachable"}
        else:
            output[key] = {
                "verdict": "reachable",
                "entry_point": path[0]["name"],
                "call_chain": [
                    {"function": fn["name"], "file": fn["file"], "line": fn["start_line"]}
                    for fn in path
                ],
            }

    return output


def main() -> None:
    if len(sys.argv) != 4:
        logger.error("[!] Usage: %s <clone_dir> <sarif_file> <output_file>", sys.argv[0])
        sys.exit(1)

    clone_dir, sarif_file, output_file = sys.argv[1], sys.argv[2], sys.argv[3]

    try:
        data = build_reachability(clone_dir, sarif_file)
    except Exception as exc:
        logger.error("[!] Reachability error: %s — writing empty output", exc)
        data = {}

    Path(output_file).write_text(json.dumps(data))

    reachable = sum(1 for v in data.values() if v.get("verdict") == "reachable")
    total = len(data)
    logger.info("[✓] Reachability: %d/%d reachable → %s", reachable, total, output_file)


if __name__ == "__main__":
    main()
