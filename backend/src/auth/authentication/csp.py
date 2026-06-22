"""Compute SHA-256 hashes of scripts for CSP allow-listing.

This is the mechanism that eliminates `'unsafe-inline'` from script-src.
Called at FastAPI startup to read the built Next.js export and produce hashes
matching what the browser will see at runtime.

A page's CSP must cover the inline `<script>` blocks Next emits (the bootstrap
and the per-page RSC flight data in `__next_f`/`__next_s`); `'unsafe-inline'` is
not used, so each one needs a hash of its text. The external `<script src=...>`
chunks are same-origin and are authorised by `'self'` in the policy, so they do
not need hashing. The inline blocks differ per page, so hashes are computed per
HTML document rather than as one global list.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path

# Inline <script>…</script> with no src attribute. Browsers hash the exact
# text between the tags (UTF-8), which is what we reproduce here.
_INLINE_SCRIPT_RE = re.compile(
    r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL
)
# next/script beforeInteractive entries are queued in a `self.__next_s.push([...])`
# wrapper and re-injected at runtime as a *fresh* inline <script> whose body is
# the wrapper's `children` field. That injected script needs its own hash.
_NEXT_S_PUSH_RE = re.compile(r"self\.__next_s.*?\.push\((\[.*\])\)", re.DOTALL)


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _next_s_injected_bodies(script_body: str) -> list[str]:
    """Inline script bodies that a `__next_s` wrapper re-injects at runtime.

    Returns the `children` (or dangerouslySetInnerHTML.__html) strings carried
    in the push payload — the exact text the browser will hash when the wrapper
    inserts them as new <script> elements.
    """
    if "__next_s" not in script_body:
        return []
    match = _NEXT_S_PUSH_RE.search(script_body)
    if not match:
        return []
    try:
        payload = json.loads(match.group(1))
    except (json.JSONDecodeError, ValueError):
        return []

    bodies: list[str] = []

    def _walk(node: object) -> None:
        if isinstance(node, dict):
            child = node.get("children")
            if isinstance(child, str):
                bodies.append(child)
            dsi = node.get("dangerouslySetInnerHTML")
            if isinstance(dsi, dict) and isinstance(dsi.get("__html"), str):
                bodies.append(dsi["__html"])
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for value in node:
                _walk(value)

    _walk(payload)
    return bodies


def compute_inline_script_hashes(root: Path, pattern: str = "**/*.js") -> list[str]:
    """Return base64-encoded SHA-256 hashes of every file matching pattern under root.

    Deterministic: results are sorted by path for hash list stability. Default
    pattern is recursive (`**/*.js`) so Next.js chunks under `_next/static/chunks/`
    are picked up without callers having to know the layout.
    """
    hashes: list[str] = []
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        hashes.append(_sha256_b64(path.read_bytes()))
    return hashes


def inline_script_hashes_for_html(html_text: str) -> list[str]:
    """Hashes of the inline scripts on one exported HTML page.

    Covers both the inline `<script>` bodies present in the markup and any
    script a `__next_s` wrapper re-injects at runtime (e.g. the no-flash theme
    script). Browsers hash the exact text (UTF-8). External `<script src>`
    chunks are same-origin and covered by `'self'`, so they need no hash.
    Returns a sorted, de-duplicated list so the resulting CSP is stable.
    """
    hashes: set[str] = set()
    for body in _INLINE_SCRIPT_RE.findall(html_text):
        hashes.add(_sha256_b64(body.encode("utf-8")))
        # Also hash any script the body re-injects at runtime (next/script).
        for injected in _next_s_injected_bodies(body):
            hashes.add(_sha256_b64(injected.encode("utf-8")))
    return sorted(hashes)
