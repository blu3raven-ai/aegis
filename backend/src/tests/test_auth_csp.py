"""CSP hash computation utility tests."""
import tempfile
from pathlib import Path

from src.auth.csp import compute_inline_script_hashes


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
