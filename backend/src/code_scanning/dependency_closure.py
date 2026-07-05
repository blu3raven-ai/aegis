"""One-hop cross-file expansion for SAST delta scans (v1.1).

Given a set of changed files, returns those files PLUS:
  - files that import any changed file (reverse hop — dependents)
  - files imported by any changed file (forward hop — dependencies)

Only files present in all_repo_files are included in the result, so the
caller never receives phantom paths.
"""
from __future__ import annotations

from pathlib import Path

from src.code_scanning.import_graph import parse_imports


def compute_one_hop_closure(
    changed_files: list[str],
    all_repo_files: list[str],
    checkout_path: Path,
) -> set[str]:
    """Return changed_files ∪ one-hop dependents ∪ one-hop dependencies.

    Resolution is best-effort — specifiers that cannot be matched to a known
    repo file are silently ignored so a single unresolvable import never
    blocks the rest of the scan.
    """
    closure: set[str] = set(changed_files)
    files_set = set(all_repo_files)

    # Build both indexes in a single pass over all repo files to avoid
    # reading files twice.
    # forward_index: file → raw specifiers it imports
    # reverse_index: resolved-repo-path → set of files that import it
    forward_index: dict[str, list[str]] = {}
    reverse_index: dict[str, set[str]] = {}

    for repo_file in all_repo_files:
        full_path = checkout_path / repo_file
        if not full_path.is_file():
            continue
        try:
            content = full_path.read_text(errors="replace")
        except OSError:
            continue
        specifiers = parse_imports(full_path, content)
        forward_index[repo_file] = specifiers
        for spec in specifiers:
            resolved = _try_resolve(spec, repo_file, files_set)
            if resolved:
                reverse_index.setdefault(resolved, set()).add(repo_file)

    # Forward hop: files that are imported by any changed file
    for f in changed_files:
        for spec in forward_index.get(f, []):
            resolved = _try_resolve(spec, f, files_set)
            if resolved:
                closure.add(resolved)

    # Reverse hop: files that import any changed file
    for f in changed_files:
        closure.update(reverse_index.get(f, set()))

    return closure


def _try_resolve(
    spec: str,
    importing_file: str,
    files_set: set[str],
) -> str | None:
    """Map a raw import specifier to a repo-relative path, or return None.

    Handles three forms:
      - JS/TS relative:  './utils', '../lib/foo', './Button'
      - Python relative: '.utils', '..models'  (leading dots, no slash)
      - Absolute/package: 'pathlib', 'lib/foo'
    """
    candidates: list[str] = []
    importer_dir = Path(importing_file).parent

    if spec.startswith("./") or spec.startswith("../"):
        # JS/TS relative path — resolve directly from importer's directory
        # e.g. './utils' from 'src/app.js' → 'src/utils'
        module_path = str(importer_dir / spec)
        for ext in (".py", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"):
            candidates.append(f"{module_path}{ext}")
        # Spec may already include extension (e.g. './x.js')
        candidates.append(module_path)

    elif spec.startswith("."):
        # Python relative import — dots mean parent-directory hops
        # '.utils' → same package, '..models' → one level up
        dots = len(spec) - len(spec.lstrip("."))
        bare = spec.lstrip(".")
        base = importer_dir
        for _ in range(dots - 1):
            base = base.parent
        module_path = bare.replace(".", "/") if bare else ""
        if module_path:
            for ext in (".py", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"):
                candidates.append(str(base / f"{module_path}{ext}"))
            candidates.append(str(base / module_path))

    else:
        # Absolute / package specifier — try as repo-root relative path
        # Convert Python dot-notation to path separators (a.b.c → a/b/c)
        module_path = spec.replace(".", "/")
        for ext in (".py", ".ts", ".tsx", ".js", ".jsx", "/index.ts", "/index.js"):
            candidates.append(f"{module_path}{ext}")
        candidates.append(spec)

    for cand in candidates:
        # Normalise away any '..' components introduced by Path arithmetic
        try:
            normalised = str(Path(cand))
        except Exception:
            normalised = cand
        if normalised in files_set:
            return normalised

    return None
