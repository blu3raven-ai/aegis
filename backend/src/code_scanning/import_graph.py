"""Best-effort import parser for cross-file taint expansion (v1.1 one-hop).

Extracts the raw import specifiers written in a source file. Resolution to
actual repo paths is handled by compute_one_hop_closure so this module stays
pure (no filesystem access).
"""
from __future__ import annotations

import re
from pathlib import Path

# Python: match 'from [dots][module] import ...' or 'import a, b, c [as x]'
# Group 1: relative dots (may be empty string), Group 2: module after 'from'
# Group 3: everything after 'import ' (may be comma-separated list)
_PY_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+(\.{0,2})(\S+)\s+import|import\s+(.+))",
    re.MULTILINE,
)

# JS/TS: match the quoted specifier in import/require statements
_JS_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:.+?\s+from\s+)?|require\(\s*)["']([^"']+)["']"""
)


def parse_imports(file_path: Path, content: str) -> list[str]:
    """Return the import specifiers written in *content*, best-effort.

    Returns specifiers exactly as written (e.g. './utils' or 'lib.foo') —
    not resolved filesystem paths. Resolution is compute_one_hop_closure's job.
    Returns an empty list for unsupported languages or unparseable files.
    """
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        return _parse_python_imports(content)
    if suffix in {".js", ".ts", ".jsx", ".tsx", ".mjs"}:
        return _parse_js_imports(content)
    return []


def _parse_python_imports(content: str) -> list[str]:
    imports: list[str] = []
    for match in _PY_IMPORT_RE.finditer(content):
        relative_prefix, module_from, module_import = match.groups()
        module = module_from or module_import
        if not module:
            continue
        # Handle 'import a, b, c' and 'import os as operating_system'
        for part in module.split(","):
            name = part.strip().split(" as ")[0].split(".")[0]
            if name:
                imports.append(f"{relative_prefix or ''}{name}")
    return imports


def _parse_js_imports(content: str) -> list[str]:
    return [m.group(1) for m in _JS_IMPORT_RE.finditer(content)]
