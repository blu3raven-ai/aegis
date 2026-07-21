"""Identify the files an AI coding agent auto-loads as instructions or config.

These are the files whose *content* a coding agent (Claude Code, Cursor, Copilot,
Gemini CLI, …) reads and acts on: rules/memory files, per-tool config, MCP server
definitions, and skills. They are the blast radius for agent-targeted attacks, so
the detectors focus here rather than scanning every source file — which keeps the
signal high and the false-positive rate low.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

# Exact basenames that agents auto-load, at any depth in the tree.
_INSTRUCTION_BASENAMES = frozenset({
    "CLAUDE.md",
    "AGENTS.md",
    "GEMINI.md",
    ".cursorrules",
    ".clinerules",
    ".windsurfrules",
    ".aider.conf.yml",
    "copilot-instructions.md",
    "SKILL.md",
    ".mcp.json",
    ".roomodes",
    ".pre-commit-config.yaml",
})

# Directory trees whose contents an agent loads (settings, hooks, commands,
# subagents, skills). Matched as a path prefix (relative, POSIX separators).
_INSTRUCTION_DIR_PREFIXES = (
    ".claude/",
    ".cursor/rules/",
    ".github/",  # narrowed to copilot-instructions.md below
)

# Explicit relative paths (config that lives at a fixed location).
_INSTRUCTION_PATHS = frozenset({
    ".github/copilot-instructions.md",
    ".vscode/settings.json",
    ".vscode/mcp.json",
    ".vscode/extensions.json",
    ".vscode/launch.json",
    ".cursor/mcp.json",
    ".cursor/permissions.json",
    ".cursor/cli.json",
    ".cursor/environment.json",
    ".gemini/settings.json",
    ".amazonq/mcp.json",
    ".codex/config.toml",
    ".continue/config.yaml",
    ".continue/config.json",
    ".zed/tasks.json",
    ".zed/debug.json",
})

# Directories never worth walking — vendored code, build output, VCS internals.
_SKIP_DIRS = frozenset({
    ".git", "node_modules", ".venv", "venv", "dist", "build", ".next",
    "out", "target", "__pycache__", ".mypy_cache", ".pytest_cache", "vendor",
})

# Only text files an agent would read as instructions/config.
_ALLOWED_SUFFIXES = frozenset({".md", ".mdc", ".json", ".yml", ".yaml", ".toml", ".txt"})

# Skip anything larger than this — instruction/config files are small; a huge
# match is almost certainly a data file that happens to sit under a config dir.
_MAX_FILE_BYTES = 2 * 1024 * 1024


def is_agent_instruction_file(rel_path: str) -> bool:
    """True if ``rel_path`` (relative, POSIX-style) is agent-loaded content."""
    rel_path = rel_path.replace(os.sep, "/").lstrip("/")
    base = rel_path.rsplit("/", 1)[-1]

    if base in _INSTRUCTION_BASENAMES:
        return True
    if rel_path in _INSTRUCTION_PATHS:
        return True

    suffix = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if suffix not in _ALLOWED_SUFFIXES:
        return False
    if rel_path.startswith(".claude/"):
        return True
    if rel_path.startswith(".cursor/rules/") and suffix == ".mdc":
        return True
    if rel_path.startswith(".amazonq/cli-agents/") and suffix == ".json":
        return True
    if rel_path.startswith(".windsurf/workflows/") and suffix == ".md":
        return True
    if rel_path.startswith(".gemini/commands/") and suffix == ".toml":
        return True
    return False


def iter_target_files(repo_root: str) -> Iterator[tuple[Path, str]]:
    """Yield (absolute_path, relative_posix_path) for each agent-instruction file.

    Walks ``repo_root``, pruning vendored/build directories, and skips files
    above the size cap (likely data, not instructions).
    """
    root = Path(repo_root)
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip-dirs in place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            abs_path = Path(dirpath) / name
            try:
                rel = abs_path.relative_to(root).as_posix()
            except ValueError:
                continue
            if not is_agent_instruction_file(rel):
                continue
            try:
                if abs_path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield abs_path, rel
