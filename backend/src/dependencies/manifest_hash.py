"""Deterministic manifest-set hash for dependency files.

The hash captures which lockfiles + manifests exist and what they contain,
so that two checkouts with identical dependency manifests produce the same hash
even if files were written in a different order.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

# Lockfiles and manifests that fully determine the dependency graph.
# Recognised by filename only — path may vary (monorepo, nested packages, etc.).
_MANIFEST_NAMES: frozenset[str] = frozenset({
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "poetry.lock",
    "Pipfile.lock",
    "Cargo.lock",
    "composer.lock",
    "Gemfile.lock",
    "Gemfile",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "mix.exs",
})

# Directories whose contents must be excluded from the manifest set.
# Scanning inside these would pick up vendored/cached dependency copies that
# don't represent the project's own declared dependencies.
_EXCLUDED_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    ".venv",
    "vendor",
})


def compute_manifest_set_hash(checkout_path: Path) -> str:
    """Return a stable SHA-256 over the set of manifest files found under checkout_path.

    Hash input is the sorted concatenation of ``relative/path|sha256_of_content\n``
    lines, one per recognised manifest file discovered recursively (excluded dirs
    are skipped).  Sorting by path makes the result independent of filesystem
    traversal order.

    Returns a 64-character lowercase hex digest.
    """
    if not checkout_path.exists():
        raise FileNotFoundError(f"checkout_path does not exist: {checkout_path}")

    entries: list[tuple[str, str]] = []

    for candidate in checkout_path.rglob("*"):
        if not candidate.is_file():
            continue

        # Skip any path that passes through an excluded directory
        rel = candidate.relative_to(checkout_path)
        if any(part in _EXCLUDED_DIRS for part in rel.parts[:-1]):
            continue

        if candidate.name not in _MANIFEST_NAMES:
            continue

        content_sha = hashlib.sha256(candidate.read_bytes()).hexdigest()
        entries.append((str(rel), content_sha))

    # Sort by relative path for determinism regardless of traversal order
    entries.sort(key=lambda e: e[0])

    digest_input = "".join(f"{path}|{sha}\n" for path, sha in entries).encode()
    return hashlib.sha256(digest_input).hexdigest()
