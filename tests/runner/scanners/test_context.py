"""Tests for the shared code-window extraction (runner/scanners/_context.py)."""
from __future__ import annotations

from runner.scanners._context import code_window, read_code_window


def test_code_window_centers_and_is_1_indexed():
    lines = [f"line{i}" for i in range(1, 101)]  # line1..line100
    text, start = code_window(lines, 50, radius=5)
    assert start == 45
    assert text.splitlines() == [f"line{i}" for i in range(45, 56)]


def test_code_window_clamps_at_file_start():
    text, start = code_window(["a", "b", "c"], 1, radius=5)
    assert start == 1
    assert text == "a\nb\nc"


def test_read_code_window_relative(tmp_path):
    (tmp_path / "f.py").write_text("\n".join(f"x{i}" for i in range(1, 21)))
    text, start = read_code_window(tmp_path, "f.py", 10, radius=2)
    assert start == 8
    assert "x10" in text


def test_read_code_window_absolute_inside_root(tmp_path):
    f = tmp_path / "sub" / "g.py"
    f.parent.mkdir()
    f.write_text("one\ntwo\nthree")
    text, _ = read_code_window(tmp_path, str(f), 2, radius=1)
    assert "two" in text


def test_read_code_window_rejects_escape(tmp_path):
    (tmp_path / "in.py").write_text("ok")
    outside = tmp_path.parent / "secret.txt"
    outside.write_text("SHOULD NOT BE READ")
    assert read_code_window(tmp_path, "../secret.txt", 1) == (None, None)
    assert read_code_window(tmp_path, str(outside), 1) == (None, None)


def test_read_code_window_missing_or_bad_line(tmp_path):
    assert read_code_window(tmp_path, "nope.py", 1) == (None, None)
    (tmp_path / "f.py").write_text("a\nb")
    assert read_code_window(tmp_path, "f.py", 0) == (None, None)


def test_read_code_window_applies_redact(tmp_path):
    (tmp_path / "s.env").write_text("API_KEY=supersecret123\nOTHER=ok")
    text, _ = read_code_window(
        tmp_path, "s.env", 1, redact=lambda t: t.replace("supersecret123", "X")
    )
    assert "supersecret123" not in text
    assert "X" in text


# --- resolve_in_root: scanner-path -> real file (the _checkout double-prefix fix)

def test_resolve_in_root_reanchors_checkout_prefix(tmp_path):
    from runner.scanners._context import resolve_in_root

    # `tmp_path` stands in for the clone_dir (".../<repo>/_checkout"). semgrep
    # emits the absolute target, so after the temp-prefix strip the path still
    # carries the "<repo>/_checkout/" prefix and double-counts when joined.
    (tmp_path / "server.py").write_text("x")
    got = resolve_in_root(tmp_path, "ilmu-asr-poc/_checkout/server.py")
    assert got == (tmp_path / "server.py").resolve()


def test_resolve_in_root_prefers_original_clean_path(tmp_path):
    from runner.scanners._context import resolve_in_root

    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f.py").write_text("x")
    assert resolve_in_root(tmp_path, "sub/f.py") == (tmp_path / "sub" / "f.py").resolve()


def test_resolve_in_root_jails_escape_and_missing(tmp_path):
    from runner.scanners._context import resolve_in_root

    assert resolve_in_root(tmp_path, "../../etc/passwd") is None
    assert resolve_in_root(tmp_path, "nope.py") is None
    assert resolve_in_root(tmp_path, "") is None


def test_read_code_window_resolves_through_checkout_prefix(tmp_path):
    # Before the fix this returned (None, None) — the SAST "No code captured" bug.
    (tmp_path / "server.py").write_text("\n".join(f"l{i}" for i in range(1, 21)))
    text, start = read_code_window(tmp_path, "ilmu-asr-poc/_checkout/server.py", 10, radius=2)
    assert start == 8
    assert "l10" in text
