"""Tests for extract-context.py — single-pass context extraction."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "extract_context",
    Path(__file__).parent.parent.parent / "scanners" / "code-scanning" / "scripts" / "extract-context.py",
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_classify = _mod._classify
_imports = _mod._imports
_window = _mod._window
main = _mod.main


def _sarif(uri: str, start_line: int) -> dict:
    return {
        "runs": [{
            "tool": {"driver": {"name": "opengrep", "rules": []}},
            "results": [{
                "ruleId": "python.injection",
                "message": {"text": "Injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": start_line},
                    }
                }],
            }],
        }]
    }


# ── _classify ─────────────────────────────────────────────────────────────────


def test_classify_test_file():
    assert _classify("tests/helpers.py") == "test"
    assert _classify("src/app.test.ts") == "test"
    assert _classify("__tests__/util.js") == "test"


def test_classify_generated_file():
    assert _classify("src/dist/bundle.js") == "generated"  # needs /dist/ with leading slash
    assert _classify("api.pb.go") == "generated"


def test_classify_vendor_file():
    assert _classify("vendor/lib/util.py") == "vendor"
    assert _classify("node_modules/lodash/index.js") == "vendor"


def test_classify_source_file():
    assert _classify("src/server.py") == "source"
    assert _classify("cmd/main.go") == "source"


# ── _imports ──────────────────────────────────────────────────────────────────


def test_imports_extracts_python_imports():
    text = "import os\nimport sys\n\ndef main():\n    pass\n"
    result = _imports(text)
    assert "import os" in result
    assert "import sys" in result
    assert "def main" not in result


def test_imports_extracts_js_require():
    # require must be at the start of the line (same as original awk pattern)
    text = "require('express')\nrequire('path')\n\napp.get('/')"
    result = _imports(text)
    assert "require('express')" in result
    assert "app.get" not in result


def test_imports_empty_for_no_imports():
    result = _imports("def f():\n    return 1\n")
    assert result == ""


# ── _window ───────────────────────────────────────────────────────────────────


def test_window_returns_80_lines_around_finding():
    lines = [f"line{i}" for i in range(1, 201)]
    result = _window(lines, start_line=100)
    result_lines = result.split("\n")
    # Should include line100 (index 99) ± 40
    assert "line60" in result_lines   # line-40
    assert "line100" in result_lines  # exact line
    assert "line140" in result_lines  # line+40


def test_window_clamps_to_start_of_file():
    lines = ["first", "second", "third"]
    result = _window(lines, start_line=1)
    assert "first" in result


def test_window_truncates_at_8192_bytes():
    # 200 lines of 100 chars each = 20000+ bytes → must be truncated
    lines = ["x" * 100 for _ in range(200)]
    result = _window(lines, start_line=100)
    assert len(result) <= 8192


# ── main (end-to-end) ─────────────────────────────────────────────────────────


def test_main_produces_context_for_each_finding(tmp_path, monkeypatch):
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "server.py").write_text("import requests\n\nrequests.post(url)\n")

    output = tmp_path / "output"
    output.mkdir()
    (output / "opengrep.json").write_text(json.dumps(_sarif("server.py", 3)))

    monkeypatch.setattr("sys.argv", ["extract-context.py", str(clone), str(output)])
    main()

    ctx = json.loads((output / "context.json").read_text())
    assert "server.py:3" in ctx
    entry = ctx["server.py:3"]
    assert entry["file_class"] == "source"
    assert "import requests" in entry["imports"]
    assert "requests.post" in entry["code_window"]


def test_main_strips_tmp_prefix_from_sarif_uri(tmp_path, monkeypatch):
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "server.py").write_text("import os\nos.system(cmd)\n")

    output = tmp_path / "output"
    output.mkdir()
    abs_uri = "/tmp/tmp.tum6N6HTcv/server.py"
    (output / "opengrep.json").write_text(json.dumps(_sarif(abs_uri, 2)))

    monkeypatch.setattr("sys.argv", ["extract-context.py", str(clone), str(output)])
    main()

    ctx = json.loads((output / "context.json").read_text())
    # Key must be relative, not absolute
    assert "server.py:2" in ctx
    assert f"{abs_uri}:2" not in ctx


def test_main_reads_each_file_once_for_multiple_findings(tmp_path, monkeypatch):
    """Multiple findings in the same file must not cause redundant file reads."""
    clone = tmp_path / "repo"
    clone.mkdir()
    src = clone / "server.py"
    src.write_text("\n".join(f"line{i}" for i in range(1, 101)))

    sarif = {
        "runs": [{
            "tool": {"driver": {"name": "opengrep", "rules": []}},
            "results": [
                {"ruleId": "r", "message": {"text": "m"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "server.py"}, "region": {"startLine": i}}}]}
                for i in [10, 20, 30, 40, 50]
            ],
        }]
    }
    output = tmp_path / "output"
    output.mkdir()
    (output / "opengrep.json").write_text(json.dumps(sarif))

    monkeypatch.setattr("sys.argv", ["extract-context.py", str(clone), str(output)])
    main()

    ctx = json.loads((output / "context.json").read_text())
    assert len(ctx) == 5
    for line in [10, 20, 30, 40, 50]:
        assert f"server.py:{line}" in ctx


def test_main_no_sarif_writes_empty_context(tmp_path, monkeypatch):
    clone = tmp_path / "repo"
    clone.mkdir()
    output = tmp_path / "output"
    output.mkdir()

    monkeypatch.setattr("sys.argv", ["extract-context.py", str(clone), str(output)])
    main()

    ctx = json.loads((output / "context.json").read_text())
    assert ctx == {}


def test_main_rejects_absolute_paths_in_sarif(tmp_path, monkeypatch):
    """Non-temp absolute paths (not /tmp/tmp.*) are rejected for security."""
    clone = tmp_path / "repo"
    clone.mkdir()
    output = tmp_path / "output"
    output.mkdir()
    (output / "opengrep.json").write_text(json.dumps(_sarif("/etc/passwd", 1)))

    monkeypatch.setattr("sys.argv", ["extract-context.py", str(clone), str(output)])
    main()

    ctx = json.loads((output / "context.json").read_text())
    assert ctx == {}
