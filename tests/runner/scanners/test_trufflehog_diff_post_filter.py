"""Trufflehog filesystem diff post-filter: _apply_diff_scope."""
from __future__ import annotations


def _finding(file_path: str, secret: str = "AKIA...") -> dict:
    return {
        "SourceMetadata": {"Data": {"Filesystem": {"file": file_path, "line": 1}}},
        "DetectorName": "AWS",
        "Raw": secret,
    }


def test_filesystem_findings_filtered_to_diff_file_set(monkeypatch):
    from runner.scanners.secrets import scanner as s

    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *_a, **_kw: ["src/a.py"],
    )

    raw = [
        _finding("/tmp/clone/src/a.py", "AKIA..."),
        _finding("/tmp/clone/src/b.py", "ghp_..."),
    ]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha="deadbeef",
        head_sha="cafebabe",
    )
    assert out == [_finding("/tmp/clone/src/a.py", "AKIA...")]


def test_apply_diff_scope_noop_when_base_sha_missing(monkeypatch):
    from runner.scanners.secrets import scanner as s

    called = []
    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *a, **kw: called.append(a) or [],
    )

    raw = [_finding("/tmp/clone/src/a.py")]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha=None,
        head_sha="cafebabe",
    )
    assert out == raw
    assert not called


def test_apply_diff_scope_noop_when_head_sha_missing(monkeypatch):
    from runner.scanners.secrets import scanner as s

    called = []
    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *a, **kw: called.append(a) or [],
    )

    raw = [_finding("/tmp/clone/src/a.py")]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha="deadbeef",
        head_sha=None,
    )
    assert out == raw
    assert not called


def test_apply_diff_scope_noop_when_both_sha_missing(monkeypatch):
    from runner.scanners.secrets import scanner as s

    raw = [_finding("/tmp/clone/src/a.py")]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha=None,
        head_sha=None,
    )
    assert out == raw


def test_apply_diff_scope_all_filtered_when_no_overlap(monkeypatch):
    from runner.scanners.secrets import scanner as s

    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *_a, **_kw: ["other/file.py"],
    )

    raw = [_finding("/tmp/clone/src/a.py"), _finding("/tmp/clone/src/b.py")]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha="deadbeef",
        head_sha="cafebabe",
    )
    assert out == []


def test_apply_diff_scope_clone_dir_trailing_slash(monkeypatch):
    """clone_dir with trailing slash should still match correctly."""
    from runner.scanners.secrets import scanner as s

    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *_a, **_kw: ["src/a.py"],
    )

    raw = [_finding("/tmp/clone/src/a.py"), _finding("/tmp/clone/src/b.py")]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone/",
        base_sha="deadbeef",
        head_sha="cafebabe",
    )
    assert len(out) == 1
    assert out[0]["SourceMetadata"]["Data"]["Filesystem"]["file"] == "/tmp/clone/src/a.py"


def test_apply_diff_scope_path_outside_clone_dir_kept(monkeypatch):
    """A finding whose path is outside the clone dir must be kept (fail open).

    Silently dropping an unrecognised path risks hiding real secrets — we can't
    determine scope, so the safe default is to keep the finding for review.
    """
    from runner.scanners.secrets import scanner as s

    monkeypatch.setattr(
        "runner.scanners.secrets.scanner.compute_diff_files",
        lambda *_a, **_kw: ["src/a.py"],
    )

    outside = _finding("/etc/secret.txt", "AKIA_OUTSIDE")
    inside = _finding("/tmp/clone/src/a.py", "AKIA_INSIDE")
    raw = [outside, inside]
    out = s._apply_diff_scope(
        findings=raw,
        clone_dir="/tmp/clone",
        base_sha="deadbeef",
        head_sha="cafebabe",
    )
    # Both kept: the outside-clone finding is kept fail-open, the inside one matches diff.
    assert len(out) == 2
    paths = [f["SourceMetadata"]["Data"]["Filesystem"]["file"] for f in out]
    assert "/etc/secret.txt" in paths
    assert "/tmp/clone/src/a.py" in paths
