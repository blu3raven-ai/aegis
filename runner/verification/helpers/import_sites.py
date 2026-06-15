"""Locate where user code imports a given third-party package (npm + pip)."""
from __future__ import annotations

import dataclasses
import logging
import os
import re
from collections.abc import Iterable
from pathlib import Path

logger = logging.getLogger(__name__)


_DEFAULT_MAX_SITES = 5
_DEFAULT_CONTEXT_LINES = 2
_MAX_FILE_BYTES = 1_000_000  # skip files >1MB; imports live near the top of small files

_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
        "out",
        "coverage",
        ".cache",
        "vendor",
        "target",
        ".gradle",
    }
)

_JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")
_PY_EXTENSIONS = (".py", ".pyi")


@dataclasses.dataclass(frozen=True)
class ImportSite:
    file: str            # repo-relative POSIX path
    line: int            # 1-indexed
    snippet: str         # the import line plus ±context_lines of context
    kind: str            # "import" | "require" | "from_import" | "dynamic_import"

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "kind": self.kind,
        }


def find_import_sites(
    repo_dir: Path,
    package_name: str,
    ecosystem: str,
    *,
    max_sites: int = _DEFAULT_MAX_SITES,
    context_lines: int = _DEFAULT_CONTEXT_LINES,
    extra_excluded_dirs: Iterable[str] = (),
) -> list[ImportSite]:
    """Return up to ``max_sites`` import sites of ``package_name``. Empty when ecosystem unsupported."""
    if not repo_dir.exists() or not repo_dir.is_dir():
        return []
    if not package_name:
        return []

    matcher = _matcher_for(ecosystem, package_name)
    if matcher is None:
        return []

    excluded = _EXCLUDED_DIRS | frozenset(extra_excluded_dirs)
    try:
        repo_root = repo_dir.resolve()
    except OSError:
        return []

    sites: list[ImportSite] = []
    for file_path in _walk_source_files(repo_root, matcher.extensions, excluded):
        if len(sites) >= max_sites:
            break
        try:
            file_sites = _scan_file(
                file_path,
                repo_root=repo_root,
                matcher=matcher,
                context_lines=context_lines,
                remaining=max_sites - len(sites),
            )
        except OSError as exc:
            logger.debug("skipping %s: %s", file_path, exc)
            continue
        sites.extend(file_sites)

    return sites[:max_sites]


# ---------------------------------------------------------------------------
# internal — per-ecosystem matchers
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class _Matcher:
    extensions: tuple[str, ...]
    patterns: tuple[tuple[re.Pattern[str], str], ...]  # (compiled regex, kind)


def _matcher_for(ecosystem: str, package_name: str) -> _Matcher | None:
    eco = (ecosystem or "").lower()
    if eco in ("npm", "javascript", "typescript", "node"):
        return _npm_matcher(package_name)
    if eco in ("pypi", "python", "pip"):
        return _pip_matcher(package_name)
    return None


def _npm_matcher(package_name: str) -> _Matcher:
    # Matches both quote styles; subpath imports ("lodash/get") count as the package.
    name = re.escape(package_name)
    quoted = rf"['\"]{name}(?:/[^'\"]+)?['\"]"
    patterns = (
        (
            re.compile(rf"require\s*\(\s*{quoted}\s*\)"),
            "require",
        ),
        (
            re.compile(rf"(?:^|\b)(?:import|export)\b[^;\n]*?from\s*{quoted}"),
            "import",
        ),
        (
            re.compile(rf"(?:^|\b)import\s*{quoted}"),
            "import",
        ),
        (
            re.compile(rf"import\s*\(\s*{quoted}\s*\)"),
            "dynamic_import",
        ),
    )
    return _Matcher(extensions=_JS_EXTENSIONS, patterns=patterns)


def _pip_matcher(package_name: str) -> _Matcher:
    # pip name often differs from import name; try registered + common shape transforms.
    candidates = _pip_import_candidates(package_name)
    alt = "|".join(re.escape(c) for c in sorted(candidates, key=len, reverse=True))
    name_group = rf"(?:{alt})"

    boundary = r"(?:$|[\s,;.])"
    patterns = (
        (
            re.compile(
                rf"^\s*from\s+{name_group}(?:\.[A-Za-z_][\w]*)*\s+import\b",
                re.MULTILINE,
            ),
            "from_import",
        ),
        (
            re.compile(
                rf"^\s*import\s+{name_group}(?:\.[A-Za-z_][\w]*)*{boundary}",
                re.MULTILINE,
            ),
            "import",
        ),
    )
    return _Matcher(extensions=_PY_EXTENSIONS, patterns=patterns)


def _pip_import_candidates(package_name: str) -> set[str]:
    """Best-effort pip-name → import-name transformations."""
    base = package_name.strip()
    candidates: set[str] = {base, base.lower()}
    candidates.add(base.replace("-", "_"))
    candidates.add(base.lower().replace("-", "_"))
    candidates.add(base.replace(".", "_"))
    # Drop any candidate that's not a valid Python identifier prefix —
    # avoids accidentally generating patterns that match unrelated code.
    return {c for c in candidates if c and re.match(r"^[A-Za-z_][\w]*$", c)}


# ---------------------------------------------------------------------------
# internal — file walking + scanning
# ---------------------------------------------------------------------------


def _walk_source_files(
    repo_root: Path,
    extensions: tuple[str, ...],
    excluded: frozenset[str],
) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(repo_root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in excluded and not d.startswith(".")]
        for name in filenames:
            if not name.endswith(extensions):
                continue
            yield Path(dirpath) / name


def _scan_file(
    file_path: Path,
    *,
    repo_root: Path,
    matcher: _Matcher,
    context_lines: int,
    remaining: int,
) -> list[ImportSite]:
    try:
        resolved = file_path.resolve()
        resolved.relative_to(repo_root)
    except (OSError, ValueError):
        return []
    try:
        size = resolved.stat().st_size
    except OSError:
        return []
    if size > _MAX_FILE_BYTES or size == 0:
        return []
    try:
        text = resolved.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if "\x00" in text[:1024]:
        return []

    lines = text.splitlines()
    rel_path = resolved.relative_to(repo_root).as_posix()
    sites: list[ImportSite] = []

    matched_lines: dict[int, str] = {}  # 1-indexed line → kind (dedup)
    for pattern, kind in matcher.patterns:
        for m in pattern.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            matched_lines.setdefault(line_no, kind)
            if len(matched_lines) >= remaining:
                break
        if len(matched_lines) >= remaining:
            break

    for line_no in sorted(matched_lines):
        sites.append(
            ImportSite(
                file=rel_path,
                line=line_no,
                snippet=_snippet(lines, line_no, context_lines),
                kind=matched_lines[line_no],
            )
        )

    return sites


def _snippet(lines: list[str], center_line: int, context: int) -> str:
    start = max(0, center_line - 1 - context)
    end = min(len(lines), center_line + context)
    return "\n".join(lines[start:end])
