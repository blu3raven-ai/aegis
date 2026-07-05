"""Tests for compute_one_hop_closure in dependency_closure.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.code_scanning.dependency_closure import compute_one_hop_closure


def _write(root: Path, rel: str, content: str = "") -> str:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    return rel


# ── Basic invariants ──────────────────────────────────────────────────────────


def test_changed_files_always_in_closure(tmp_path):
    _write(tmp_path, "a.py", "x = 1")
    result = compute_one_hop_closure(["a.py"], ["a.py"], tmp_path)
    assert "a.py" in result


def test_empty_changed_files(tmp_path):
    _write(tmp_path, "a.py")
    result = compute_one_hop_closure([], ["a.py"], tmp_path)
    assert result == set()


def test_no_imports_no_expansion(tmp_path):
    _write(tmp_path, "a.py", "x = 1")
    _write(tmp_path, "b.py", "y = 2")
    result = compute_one_hop_closure(["a.py"], ["a.py", "b.py"], tmp_path)
    assert result == {"a.py"}


# ── Forward hop (dependencies) ────────────────────────────────────────────────


def test_forward_hop_python(tmp_path):
    """Changed file imports another file → that file is pulled into closure."""
    _write(tmp_path, "utils.py", "def helper(): pass")
    _write(tmp_path, "app.py", "from utils import helper")
    result = compute_one_hop_closure(["app.py"], ["app.py", "utils.py"], tmp_path)
    assert "utils.py" in result


def test_forward_hop_js(tmp_path):
    _write(tmp_path, "src/utils.js", "export const x = 1;")
    _write(tmp_path, "src/app.js", "import { x } from './utils';")
    result = compute_one_hop_closure(
        ["src/app.js"],
        ["src/app.js", "src/utils.js"],
        tmp_path,
    )
    assert "src/utils.js" in result


def test_forward_hop_ts(tmp_path):
    _write(tmp_path, "lib/foo.ts", "export const foo = 1;")
    _write(tmp_path, "app.ts", "import { foo } from './lib/foo';")
    result = compute_one_hop_closure(
        ["app.ts"],
        ["app.ts", "lib/foo.ts"],
        tmp_path,
    )
    assert "lib/foo.ts" in result


# ── Reverse hop (dependents) ──────────────────────────────────────────────────


def test_reverse_hop_python(tmp_path):
    """Changed file is imported by another file → that other file is pulled in."""
    _write(tmp_path, "utils.py", "def helper(): pass")
    _write(tmp_path, "app.py", "from utils import helper")
    # utils.py changes; app.py depends on it
    result = compute_one_hop_closure(["utils.py"], ["app.py", "utils.py"], tmp_path)
    assert "app.py" in result


def test_reverse_hop_js(tmp_path):
    _write(tmp_path, "src/lib.js", "export const x = 1;")
    _write(tmp_path, "src/consumer.js", "import { x } from './lib';")
    result = compute_one_hop_closure(
        ["src/lib.js"],
        ["src/lib.js", "src/consumer.js"],
        tmp_path,
    )
    assert "src/consumer.js" in result


# ── Both directions ───────────────────────────────────────────────────────────


def test_both_directions_python(tmp_path):
    _write(tmp_path, "models.py", "class User: pass")
    _write(tmp_path, "services.py", "from models import User\nfrom utils import fmt")
    _write(tmp_path, "utils.py", "def fmt(): pass")
    _write(tmp_path, "views.py", "from services import do_thing")

    result = compute_one_hop_closure(
        ["services.py"],
        ["models.py", "services.py", "utils.py", "views.py"],
        tmp_path,
    )
    # forward hop: models, utils imported by services.py
    assert "models.py" in result
    assert "utils.py" in result
    # reverse hop: views.py imports services.py
    assert "views.py" in result


# ── Cycle handling ────────────────────────────────────────────────────────────


def test_cycle_does_not_cause_infinite_loop(tmp_path):
    """Mutual imports must not cause infinite recursion (one hop only)."""
    _write(tmp_path, "a.py", "from b import x")
    _write(tmp_path, "b.py", "from a import y")
    # Should return without error; one hop only, so both a and b are in closure
    result = compute_one_hop_closure(["a.py"], ["a.py", "b.py"], tmp_path)
    assert "a.py" in result
    assert "b.py" in result


def test_self_import_does_not_crash(tmp_path):
    _write(tmp_path, "a.py", "from a import x")
    result = compute_one_hop_closure(["a.py"], ["a.py"], tmp_path)
    assert "a.py" in result


# ── Files not in repo ─────────────────────────────────────────────────────────


def test_external_package_not_added(tmp_path):
    """Imports of third-party packages not in all_repo_files must be ignored."""
    _write(tmp_path, "app.py", "import requests\nfrom flask import Flask")
    result = compute_one_hop_closure(["app.py"], ["app.py"], tmp_path)
    # requests and flask are not repo files
    assert result == {"app.py"}


def test_changed_file_not_in_repo_still_included(tmp_path):
    """changed_files entries that aren't in all_repo_files pass through unchanged."""
    # Phantom file — not on disk, not in all_repo_files
    result = compute_one_hop_closure(
        ["phantom.py"],
        ["other.py"],
        tmp_path,
    )
    assert "phantom.py" in result


# ── Multiple changed files ────────────────────────────────────────────────────


def test_multiple_changed_files(tmp_path):
    _write(tmp_path, "a.py", "from shared import x")
    _write(tmp_path, "b.py", "from shared import y")
    _write(tmp_path, "shared.py", "x = y = 1")
    _write(tmp_path, "consumer.py", "from a import x\nfrom b import y")

    result = compute_one_hop_closure(
        ["a.py", "b.py"],
        ["a.py", "b.py", "shared.py", "consumer.py"],
        tmp_path,
    )
    assert "shared.py" in result   # forward hop from both a and b
    assert "consumer.py" in result  # reverse hop (consumer imports a and b)


# ── Relative Python imports ───────────────────────────────────────────────────


def test_python_relative_import_resolved(tmp_path):
    _write(tmp_path, "pkg/__init__.py", "")
    _write(tmp_path, "pkg/utils.py", "def helper(): pass")
    _write(tmp_path, "pkg/app.py", "from .utils import helper")

    result = compute_one_hop_closure(
        ["pkg/app.py"],
        ["pkg/__init__.py", "pkg/utils.py", "pkg/app.py"],
        tmp_path,
    )
    assert "pkg/utils.py" in result
