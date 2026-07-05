"""CSP hash computation utility tests."""
import base64
import hashlib
import json
import tempfile
from pathlib import Path

from src.auth.authentication.csp import (
    compute_inline_script_hashes,
    inline_script_hashes_for_html,
)


def _b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode()


def test_compute_hashes_returns_base64_sha256():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.js").write_bytes(b'console.log("hi");')
        (d / "b.js").write_bytes(b'console.log("bye");')
        hashes = compute_inline_script_hashes(d, pattern="*.js")
        assert len(hashes) == 2
        for h in hashes:
            # base64 of SHA-256 is exactly 44 chars (with padding)
            assert len(h) == 44


def test_compute_hashes_deterministic():
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "a.js").write_bytes(b'x')
        first = compute_inline_script_hashes(d, pattern="*.js")
        second = compute_inline_script_hashes(d, pattern="*.js")
        assert first == second


def test_compute_hashes_returns_empty_for_no_files():
    with tempfile.TemporaryDirectory() as tmp:
        hashes = compute_inline_script_hashes(Path(tmp), pattern="*.js")
        assert hashes == []


def test_compute_hashes_recursive_glob_finds_nested_files():
    """Default pattern is recursive — Next.js chunks live under nested dirs."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "chunks").mkdir()
        (d / "chunks" / "a.js").write_bytes(b"console.log('hi');")
        hashes = compute_inline_script_hashes(d)  # default pattern is **/*.js
        assert len(hashes) == 1


def test_compute_hashes_skips_directories():
    """A directory named with a .js suffix should not raise IsADirectoryError."""
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d / "real.js").write_bytes(b"actual content")
        (d / "fake.js").mkdir()  # directory whose name matches the pattern
        hashes = compute_inline_script_hashes(d)
        assert len(hashes) == 1  # only real.js


def test_inline_script_hashes_hashes_inline_bodies():
    """Inline <script> bodies must be hashed from their exact text content."""
    body = '(self.__next_f=self.__next_f||[]).push([0])'
    html = f"<html><body><script>{body}</script></body></html>"
    assert _b64(body.encode("utf-8")) in inline_script_hashes_for_html(html)


def test_inline_script_hashes_ignores_external_src_scripts():
    """<script src=...> chunks are same-origin (covered by 'self'), not hashed."""
    html = '<script src="/_next/static/chunks/main.js" async></script>'
    assert inline_script_hashes_for_html(html) == []


def test_inline_script_hashes_is_sorted_and_deduped():
    body = "x"
    html = f"<script>{body}</script><script>{body}</script>"
    assert inline_script_hashes_for_html(html) == [_b64(b"x")]


def test_inline_script_hashes_covers_next_s_reinjected_children():
    """next/script beforeInteractive scripts are re-injected at runtime as new
    <script> elements whose body is the wrapper's `children` — that injected
    body needs its own hash, not just the wrapper's."""
    child = "try{var t=localStorage.getItem('theme')}catch(e){}"
    wrapper = (
        '(self.__next_s=self.__next_s||[]).push([0,'
        + json.dumps({"children": child})
        + "])"
    )
    html = f"<script>{wrapper}</script>"
    hashes = inline_script_hashes_for_html(html)
    assert _b64(wrapper.encode("utf-8")) in hashes   # the wrapper itself
    assert _b64(child.encode("utf-8")) in hashes      # the re-injected body
