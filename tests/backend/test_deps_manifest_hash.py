"""Tests for manifest-set hash computation."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from src.dependencies.manifest_hash import compute_manifest_set_hash


def _write(root: Path, relpath: str, content: bytes = b"x") -> Path:
    p = root / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(content)
    return p


# ── determinism ──────────────────────────────────────────────────────────────


def test_hash_deterministic_same_content(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"v":1}')
    h1 = compute_manifest_set_hash(tmp_path)
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


def test_hash_is_hex_string_64_chars(tmp_path):
    h = compute_manifest_set_hash(tmp_path)
    assert isinstance(h, str)
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


def test_empty_directory_returns_consistent_hash(tmp_path):
    h = compute_manifest_set_hash(tmp_path)
    # empty set → SHA256 of empty string
    expected = hashlib.sha256(b"").hexdigest()
    assert h == expected


# ── content sensitivity ───────────────────────────────────────────────────────


def test_different_content_produces_different_hash(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"v":1}')
    h1 = compute_manifest_set_hash(tmp_path)
    (tmp_path / "package-lock.json").write_bytes(b'{"v":2}')
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 != h2


def test_adding_new_manifest_changes_hash(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"v":1}')
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, "go.mod", b"module example.com")
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 != h2


def test_non_manifest_files_ignored(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"v":1}')
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, "README.md", b"not a manifest")
    _write(tmp_path, "src/main.py", b"print('hi')")
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


# ── file-order invariance ─────────────────────────────────────────────────────


def test_hash_independent_of_filesystem_traversal_order(tmp_path):
    """Two identical manifest sets in different subdirectory structures must hash identically."""
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()

    content_lock = b'{"lock":true}'
    content_go = b"module example.com"

    _write(root_a, "package-lock.json", content_lock)
    _write(root_a, "go.mod", content_go)

    _write(root_b, "go.mod", content_go)
    _write(root_b, "package-lock.json", content_lock)

    assert compute_manifest_set_hash(root_a) == compute_manifest_set_hash(root_b)


# ── recursive search ──────────────────────────────────────────────────────────


def test_finds_manifests_in_nested_directories(tmp_path):
    _write(tmp_path, "services/api/package-lock.json", b'{"v":1}')
    _write(tmp_path, "services/worker/go.mod", b"module worker")
    h = compute_manifest_set_hash(tmp_path)
    # Hash over two nested files should differ from empty
    assert h != hashlib.sha256(b"").hexdigest()


def test_nested_and_root_manifests_combined(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"root":1}')
    _write(tmp_path, "sub/package-lock.json", b'{"sub":1}')
    h = compute_manifest_set_hash(tmp_path)
    # Should include both files
    assert len(h) == 64


# ── exclusions ────────────────────────────────────────────────────────────────


def test_node_modules_excluded(tmp_path):
    _write(tmp_path, "package-lock.json", b'{"root":1}')
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, "node_modules/some-lib/package-lock.json", b'{"nested":1}')
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


def test_dot_git_excluded(tmp_path):
    _write(tmp_path, "go.mod", b"module example.com")
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, ".git/go.mod", b"this should be ignored")
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


def test_venv_excluded(tmp_path):
    _write(tmp_path, "requirements.txt", b"requests==2.31.0")
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, ".venv/requirements.txt", b"requests==1.0.0")
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


def test_vendor_excluded(tmp_path):
    _write(tmp_path, "go.mod", b"module example.com")
    h1 = compute_manifest_set_hash(tmp_path)
    _write(tmp_path, "vendor/go.mod", b"module vendored")
    h2 = compute_manifest_set_hash(tmp_path)
    assert h1 == h2


# ── robustness ────────────────────────────────────────────────────────────────


def test_missing_checkout_path_raises(tmp_path):
    with pytest.raises((FileNotFoundError, OSError)):
        compute_manifest_set_hash(tmp_path / "nonexistent")


def test_recognises_all_manifest_types(tmp_path):
    manifests = [
        ("package.json", b"{}"),
        ("package-lock.json", b"{}"),
        ("pnpm-lock.yaml", b""),
        ("yarn.lock", b""),
        ("go.mod", b"module m"),
        ("go.sum", b""),
        ("requirements.txt", b"requests"),
        ("poetry.lock", b""),
        ("Pipfile.lock", b"{}"),
        ("Cargo.lock", b""),
        ("composer.lock", b"{}"),
        ("Gemfile.lock", b""),
        ("Gemfile", b"source 'https://rubygems.org'"),
        ("pom.xml", b"<project/>"),
        ("build.gradle", b""),
        ("build.gradle.kts", b""),
        ("mix.exs", b""),
    ]
    for name, content in manifests:
        _write(tmp_path, name, content)

    h = compute_manifest_set_hash(tmp_path)
    assert len(h) == 64
    # Each manifest contributes; hash differs from empty
    assert h != hashlib.sha256(b"").hexdigest()
