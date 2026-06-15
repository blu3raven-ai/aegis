"""tree-sitter call graph reachability for SAST findings.

Port of scanners/code-scanning/scripts/reachability.py. Builds a per-repo
call graph from tree-sitter ASTs, then for each finding location reports
whether the containing function is reachable from any detected entry
point (HTTP route handler, ``main``, server bootstrap, etc.).

``tree_sitter`` and ``tree_sitter_languages`` are imported lazily inside
:func:`_get_parser` so importing this module does not load any of the
~50 grammar shared libraries the package ships with - the runner agent
loads scanners on every job and eager grammar loading is multi-hundred-MB.
"""
from __future__ import annotations

import json
import logging
import re
import warnings
from collections import deque
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]*/")


def _strip_tmp_prefix(uri: str) -> str:
    """Strip /tmp/tmp.XXXX/ prefix that semgrep writes into SARIF URIs."""
    return _TEMP_PREFIX_RE.sub("", uri) or uri


# Cache of language -> parser. Populated lazily on first call.
_PARSER_CACHE: dict[str, Any] = {}
_PARSER_UNAVAILABLE = object()


def _get_parser(lang: str):
    """Return a tree-sitter parser for ``lang`` or ``None`` if unavailable.

    Lazy-imports tree_sitter_languages on first call. Parsers are cached
    per language so each one is constructed at most once per process.
    """
    cached = _PARSER_CACHE.get(lang)
    if cached is _PARSER_UNAVAILABLE:
        return None
    if cached is not None:
        return cached

    try:
        # tree-sitter internals emit a FutureWarning on older grammar packages
        warnings.filterwarnings(
            "ignore", category=FutureWarning, module="tree_sitter"
        )
        from tree_sitter_languages import get_parser as _ts_get_parser
    except ImportError:
        _PARSER_CACHE[lang] = _PARSER_UNAVAILABLE
        return None

    try:
        parser = _ts_get_parser(lang)
    except Exception:
        _PARSER_CACHE[lang] = _PARSER_UNAVAILABLE
        return None

    _PARSER_CACHE[lang] = parser
    return parser


EXTENSION_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cs": "c_sharp",
}

FUNC_DEF_TYPES = frozenset({
    "function_definition",
    "function_declaration",
    "method_declaration",
    "func_declaration",
    "method_definition",
    "method",
})

CALL_TYPES = frozenset({
    "call",
    "call_expression",
    "method_invocation",
    "invocation_expression",
    "function_call_expression",
    "method_call_expression",
})

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

DEAD_CODE_DIRS = frozenset({
    "archived", "archive", "deprecated", "legacy",
    "unused", "trash", "scratch", "old",
    "test", "tests", "spec", "specs",
    "benchmark", "benchmarks", "fixtures",
    "examples", "sample", "samples", "demo",
})


def _get_name(node) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node:
        return name_node.text.decode("utf-8", errors="replace")
    decl = node.child_by_field_name("declarator")
    if decl:
        found = _find_type(decl, "identifier")
        if found:
            return found.text.decode("utf-8", errors="replace")
    return None


def _find_type(node, typ: str):
    if node.type == typ:
        return node
    for child in node.children:
        result = _find_type(child, typ)
        if result:
            return result
    return None


def _get_callee(node) -> str | None:
    func = (
        node.child_by_field_name("function")
        or node.child_by_field_name("method")
        or node.child_by_field_name("name")
    )
    if not func:
        return None
    if func.type == "identifier":
        return func.text.decode("utf-8", errors="replace")
    for field in ("attribute", "property", "field"):
        attr = func.child_by_field_name(field)
        if attr and attr.type == "identifier":
            return attr.text.decode("utf-8", errors="replace")
    last = None
    for child in func.children:
        if child.type == "identifier":
            last = child
    return last.text.decode("utf-8", errors="replace") if last else None


def _collect_calls(node) -> list[str]:
    calls: list[str] = []

    def walk(n):
        if n.type in CALL_TYPES:
            callee = _get_callee(n)
            if callee:
                calls.append(callee)
        for child in n.children:
            if child.type not in FUNC_DEF_TYPES:
                walk(child)

    walk(node)
    return list(set(calls))


def _extract_functions(root_node, rel_path: str) -> list[dict]:
    filename = Path(rel_path).name
    file_is_entry = bool(
        ENTRY_PATH_RE.search(rel_path) or ENTRY_FILE_RE.match(filename)
    )

    functions: list[dict] = []

    def walk(node, decorator_text: str = ""):
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
            return

        for child in node.children:
            walk(child)

    walk(root_node)
    return functions


def parse_file(abs_path: Path, rel_path: str) -> list[dict]:
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


def _read_snippet(
    clone_path: Path, rel_file: str, start_line: int, n: int = 5
) -> str | None:
    try:
        abs_path = clone_path / rel_file
        lines = abs_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines()
        lo = max(0, start_line - 1)
        chunk = lines[lo: lo + n]
        if not chunk:
            return None
        stripped = [l.rstrip() for l in chunk]
        indent = min(
            (len(l) - len(l.lstrip()) for l in stripped if l.strip()),
            default=0,
        )
        return "\n".join(l[indent:] for l in stripped)
    except Exception:
        return None


def build_reachability(clone_dir: str | Path, sarif_file: str | Path) -> dict[str, Any]:
    """Build a {finding_key: verdict} map from a clone directory + SARIF file."""
    clone_path = Path(clone_dir)
    sarif_path = Path(sarif_file)

    if not sarif_path.exists():
        return {}

    try:
        sarif = json.loads(sarif_path.read_bytes())
    except Exception:
        return {}

    finding_locs: list[dict] = []
    seen: set[str] = set()
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            locs = result.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            uri = _strip_tmp_prefix(
                phys.get("artifactLocation", {}).get("uri", "")
            )
            line = phys.get("region", {}).get("startLine", 0)
            key = f"{uri}:{line}"
            if uri and line and key not in seen:
                seen.add(key)
                finding_locs.append({"file": uri, "line": line})

    if not finding_locs:
        return {}

    graph = CallGraph()
    for abs_path in clone_path.rglob("*"):
        if not abs_path.is_file():
            continue
        if any(part in SKIP_DIRS for part in abs_path.parts):
            continue
        rel = str(abs_path.relative_to(clone_path))
        for fn in parse_file(abs_path, rel):
            graph.add(fn)

    clone_prefix = str(clone_path).rstrip("/") + "/"

    output: dict[str, Any] = {}

    for loc in finding_locs:
        key = f"{loc['file']}:{loc['line']}"

        rel_file = loc["file"]
        if rel_file.startswith(clone_prefix):
            rel_file = rel_file[len(clone_prefix):]

        containing = graph.containing_function(rel_file, loc["line"])
        if containing is None:
            path_parts = frozenset(Path(rel_file).parts[:-1])
            if path_parts & DEAD_CODE_DIRS:
                output[key] = {"verdict": "unreachable"}
            else:
                output[key] = {
                    "verdict": "reachable",
                    "entry_point": "module-level",
                }
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
                    {
                        "function": fn["name"],
                        "file": fn["file"],
                        "line": fn["start_line"],
                        "snippet": _read_snippet(
                            clone_path, fn["file"], fn["start_line"]
                        ),
                    }
                    for fn in path
                ],
            }

    return output


def write_reachability(
    clone_dir: str | Path,
    sarif_file: str | Path,
    output_file: str | Path,
) -> dict[str, Any]:
    """Compute reachability and write the JSON result to ``output_file``.

    Mirrors the bash wrapper ``scripts/run-reachability.sh``: if the SARIF
    is missing or reachability raises, ``{}`` is written so downstream
    normalization keeps working.
    """
    output_path = Path(output_file)
    try:
        data = build_reachability(clone_dir, sarif_file)
    except Exception as exc:  # noqa: BLE001
        logger.error("[!] Reachability error: %s - writing empty output", exc)
        data = {}

    output_path.write_text(json.dumps(data))

    reachable = sum(1 for v in data.values() if v.get("verdict") == "reachable")
    total = len(data)
    logger.info(
        "[+] Reachability: %d/%d reachable -> %s", reachable, total, output_path
    )
    return data
