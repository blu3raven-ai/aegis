"""Shared code-window extraction for scanner findings.

A finding's "code preview" is a slice of the source file around the offending
line, so the UI can render the surrounding context with the specific row
highlighted. Some scanners emit this natively; for those that don't, the runner
reads the source file (which it has in the clone) and extracts the window here.

Used by the SAST, IaC, and secrets scanners so there is one implementation.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

# Lines of context kept on each side of the finding in the code window. Kept
# generous (not just the offending line) so the verifier/reachability have
# enclosing-function context; the preview UI highlights + scrolls to the line,
# and the window is byte-capped below.
CONTEXT_RADIUS = 40
_MAX_WINDOW_BYTES = 8192


def code_window(
    lines: list[str], start_line: int, *, radius: int = CONTEXT_RADIUS
) -> tuple[str, int]:
    """Return ``(window_text, window_start_line)``.

    A ±``radius`` slice of ``lines`` around ``start_line`` (1-indexed).
    ``window_start_line`` is the 1-indexed line number of the window's first
    line so the UI can anchor the gutter and highlight the offending line.
    """
    lo = max(0, start_line - radius - 1)
    hi = start_line + radius
    return "\n".join(lines[lo:hi])[:_MAX_WINDOW_BYTES], lo + 1


def _candidate_paths(file_path: str) -> list[str]:
    """Path variants to try against the clone root, most-specific first.

    Scanners emit the path their tool reported. semgrep/checkov are given the
    absolute scan target, so their paths carry the clone's own
    ``.../<repo>/_checkout/`` prefix even after the temp-dir prefix is stripped —
    which doubles up when joined to ``root`` (already ``.../_checkout``) and the
    file is never found. Re-anchoring on the last ``_checkout/`` segment recovers
    the clone-relative path. (The secrets scanner did this inline; it now lives
    here so every caller is resolved the same way.)
    """
    out = [file_path]
    if "_checkout/" in file_path:
        suffix = file_path.rsplit("_checkout/", 1)[1]
        if suffix and suffix not in out:
            out.append(suffix)
    return out


def resolve_in_root(root: Path | str, file_path: str) -> Path | None:
    """Resolve a scanner-emitted ``file_path`` to a real file inside ``root``.

    Repo-jailed: the resolved path must stay inside ``root`` (``..`` / out-of-root
    escapes are rejected). Tries the path as given, then the ``_checkout/``-
    re-anchored form, returning the first that exists as a file — so an absolute
    or double-prefixed path still resolves. Returns None on any failure.
    """
    if not file_path:
        return None
    root = Path(root)
    try:
        root_resolved = root.resolve()
    except OSError:
        return None
    for fp in _candidate_paths(file_path):
        cand = Path(fp)
        try:
            resolved = (cand if cand.is_absolute() else root / fp).resolve()
            resolved.relative_to(root_resolved)  # jail
        except (ValueError, OSError):
            continue
        if resolved.is_file():
            return resolved
    return None


def read_code_window(
    root: Path | str,
    file_path: str,
    line: int,
    *,
    radius: int = CONTEXT_RADIUS,
    redact: Callable[[str], str] | None = None,
) -> tuple[str | None, int | None]:
    """Read ``file_path`` and return ``(window_text, window_start_line)``.

    ``file_path`` may be relative to ``root`` or an absolute path that must
    resolve INSIDE ``root`` (repo-jailed: ``..`` and out-of-root paths are
    rejected). Returns ``(None, None)`` on any failure or path-escape, so callers
    can treat the window as best-effort. ``redact`` (when given) is applied to
    the window text — used by the secrets scanner to mask detected values.
    """
    if not file_path or line < 1:
        return None, None
    abs_path = resolve_in_root(root, file_path)
    if abs_path is None:
        return None, None
    try:
        lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None, None
    text, start = code_window(lines, line, radius=radius)
    if redact is not None:
        text = redact(text)
    return text, start
