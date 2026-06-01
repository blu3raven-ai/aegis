"""Single-pass context extraction for SAST findings.

Port of scanners/code-scanning/scripts/extract-context.py. Reads the SARIF
once, reads each source file at most once (cached), and writes
``context.json`` in a single pass with code window + imports + file_class
for each finding location.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_TEMP_PREFIX_RE = re.compile(r"^/tmp/tmp\.[^/]*/")
_IMPORT_RE = re.compile(
    r"^\s*(import |from [a-zA-Z_]|require[( ]|#include |use [a-zA-Z\\]|package [a-zA-Z])"
)
_TEST_RE = re.compile(
    r"(test|spec|mock|__tests__|fixtures|testdata|_test\.go|\.test\.)",
    re.IGNORECASE,
)
_GENERATED_RE = re.compile(r"(\.pb\.go$|\.generated\.|/dist/|/build/|\.min\.js$)")
_VENDOR_RE = re.compile(r"(^|/)vendor/|(^|/)node_modules/|(^|/)third_party/")


def _classify(path: str) -> str:
    if _TEST_RE.search(path):
        return "test"
    if _GENERATED_RE.search(path):
        return "generated"
    if _VENDOR_RE.search(path):
        return "vendor"
    return "source"


def _imports(text: str) -> str:
    result: list[str] = []
    found = False
    for line in text.splitlines()[:200]:
        if _IMPORT_RE.match(line):
            result.append(line)
            found = True
        elif found and not line.strip():
            continue
        elif found:
            break
    return "\n".join(result[:50])


def _window(lines: list[str], start_line: int) -> str:
    # start_line is 1-indexed; +/-40 lines around the finding
    lo = max(0, start_line - 41)
    hi = start_line + 40
    return "\n".join(lines[lo:hi])[:8192]


def extract_context(clone_dir: Path, repo_output_dir: Path) -> int:
    """Read ``opengrep.json`` SARIF under ``repo_output_dir`` and emit
    ``context.json`` with per-finding code window/imports/file_class.

    Returns the number of context entries written. ``context.json`` is
    written as ``{}`` when the SARIF file is missing or unparseable.
    """
    clone_dir = Path(clone_dir)
    repo_output_dir = Path(repo_output_dir)
    sarif_file = repo_output_dir / "opengrep.json"
    context_file = repo_output_dir / "context.json"

    if not sarif_file.exists():
        context_file.write_text("{}")
        return 0

    try:
        sarif = json.loads(sarif_file.read_bytes())
    except Exception:
        context_file.write_text("{}")
        return 0

    seen: set[str] = set()
    locs: list[tuple[str, int]] = []
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            raw_locs = result.get("locations", [])
            if not raw_locs:
                continue
            phys = raw_locs[0].get("physicalLocation", {})
            uri = _TEMP_PREFIX_RE.sub(
                "", phys.get("artifactLocation", {}).get("uri", "")
            )
            line = phys.get("region", {}).get("startLine", 0)
            key = f"{uri}:{line}"
            if uri and line and key not in seen:
                seen.add(key)
                locs.append((uri, line))

    try:
        clone_resolved = clone_dir.resolve()
    except OSError:
        context_file.write_text("{}")
        return 0

    file_cache: dict[str, list[str] | None] = {}

    context: dict[str, dict] = {}
    for rel_file, line in locs:
        if rel_file.startswith("/") or ".." in rel_file:
            continue

        abs_path = clone_dir / rel_file
        try:
            abs_path.resolve().relative_to(clone_resolved)
        except (ValueError, OSError):
            continue

        if rel_file not in file_cache:
            try:
                file_cache[rel_file] = (
                    abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
                )
            except Exception:
                file_cache[rel_file] = None

        lines = file_cache[rel_file]
        if lines is None:
            imp, win = "", ""
        else:
            full_text = "\n".join(lines)
            imp = _imports(full_text)
            win = _window(lines, line)

        context[f"{rel_file}:{line}"] = {
            "file_class": _classify(rel_file),
            "imports": imp,
            "code_window": win,
        }

    context_file.write_text(json.dumps(context))
    logger.info(
        "[+] Context extracted for %d findings -> %s", len(context), context_file
    )
    return len(context)
