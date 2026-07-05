"""Tests for runner.verification.tools — the agent tool-use harness."""
from __future__ import annotations

from pathlib import Path

import pytest

from runner.verification.tools.base import Tool, ToolRegistry
from runner.verification.tools.repo import (
    grep_repo,
    make_grep_repo_tool,
    make_read_file_range_tool,
    read_file_range,
)


# ---------------------------------------------------------------------------
# ToolRegistry
# ---------------------------------------------------------------------------


def _trivial_tool(name: str = "echo") -> Tool:
    return Tool(
        name=name,
        description="echoes",
        parameters={"type": "object", "properties": {"msg": {"type": "string"}}},
        handler=lambda args: f"echo: {args.get('msg', '')}",
    )


def test_registry_rejects_duplicate_tool_names():
    with pytest.raises(ValueError, match="duplicate"):
        ToolRegistry([_trivial_tool("a"), _trivial_tool("a")])


def test_registry_to_openai_spec_matches_function_call_shape():
    reg = ToolRegistry([_trivial_tool("alpha"), _trivial_tool("beta")])
    spec = reg.to_openai_spec()
    assert len(spec) == 2
    assert spec[0]["type"] == "function"
    assert spec[0]["function"]["name"] == "alpha"
    assert "description" in spec[0]["function"]
    assert "parameters" in spec[0]["function"]


def test_registry_execute_dispatches_to_handler():
    reg = ToolRegistry([_trivial_tool("echo")])
    record = reg.execute("echo", {"msg": "hi"})
    assert record.name == "echo"
    assert record.result == "echo: hi"
    assert record.error is None


def test_registry_execute_unknown_returns_error_not_raise():
    reg = ToolRegistry([_trivial_tool("a")])
    record = reg.execute("nope", {})
    assert record.error and "unknown tool" in record.error
    assert record.result == ""


def test_registry_execute_handler_exception_caught():
    def explodes(_args):
        raise RuntimeError("boom")

    reg = ToolRegistry([
        Tool(name="bad", description="", parameters={"type": "object"}, handler=explodes)
    ])
    record = reg.execute("bad", {})
    assert record.error and "RuntimeError" in record.error
    assert "boom" in record.error


def test_registry_caps_long_results():
    big = "x" * 10_000
    reg = ToolRegistry([
        Tool(name="big", description="", parameters={"type": "object"}, handler=lambda _: big)
    ])
    record = reg.execute("big", {})
    assert len(record.result) <= 4_000


def test_registry_jsonifies_non_string_result():
    reg = ToolRegistry([
        Tool(
            name="dict",
            description="",
            parameters={"type": "object"},
            handler=lambda _: {"k": 1, "v": [1, 2]},
        )
    ])
    record = reg.execute("dict", {})
    assert '"k": 1' in record.result


# ---------------------------------------------------------------------------
# grep_repo
# ---------------------------------------------------------------------------


def _seed_repo(tmp: Path):
    (tmp / "src").mkdir()
    (tmp / "src" / "app.js").write_text("const _ = require('lodash');\nconsole.log('ok');\n")
    (tmp / "src" / "other.py").write_text("import requests\nrequests.get('x')\n")
    (tmp / "node_modules").mkdir()
    (tmp / "node_modules" / "lodash.js").write_text("// vendored — must be skipped\nrequire('x');\n")
    (tmp / ".git").mkdir()
    (tmp / ".git" / "config").write_text("require('skip me')\n")


def test_grep_finds_match_with_file_line_snippet(tmp_path):
    _seed_repo(tmp_path)
    matches = grep_repo(tmp_path, r"require\('lodash'\)")
    assert len(matches) == 1
    assert matches[0].file == "src/app.js"
    assert matches[0].line == 1
    assert "lodash" in matches[0].snippet


def test_grep_skips_excluded_dirs(tmp_path):
    _seed_repo(tmp_path)
    matches = grep_repo(tmp_path, r"require\(")
    files = {m.file for m in matches}
    assert "src/app.js" in files
    # node_modules and .git must not contribute results
    assert not any(f.startswith("node_modules/") for f in files)
    assert not any(f.startswith(".git/") for f in files)


def test_grep_invalid_pattern_raises():
    with pytest.raises(ValueError):
        grep_repo(Path("."), "[unclosed")


def test_grep_nonexistent_root_returns_empty(tmp_path):
    assert grep_repo(tmp_path / "missing", "x") == []


def test_grep_bounded_at_max_matches(tmp_path):
    (tmp_path / "f.js").write_text("\n".join(["foo"] * 50))
    matches = grep_repo(tmp_path, "foo", max_matches=10)
    assert len(matches) == 10


# ---------------------------------------------------------------------------
# read_file_range
# ---------------------------------------------------------------------------


def test_read_returns_line_range(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("\n".join(f"line{i}" for i in range(1, 11)))
    out = read_file_range(tmp_path, "a.py", 3, 5)
    assert "3: line3" in out
    assert "5: line5" in out
    assert "2: line2" not in out
    assert "6: line6" not in out


def test_read_rejects_path_escape(tmp_path):
    out = read_file_range(tmp_path, "../etc/passwd", 1, 1)
    assert "outside the repo" in out


def test_read_returns_message_on_missing_file(tmp_path):
    out = read_file_range(tmp_path, "nope.py", 1, 5)
    assert "not found" in out


def test_read_caps_line_count(tmp_path):
    p = tmp_path / "big.txt"
    p.write_text("\n".join(f"l{i}" for i in range(1, 1000)))
    out = read_file_range(tmp_path, "big.txt", 1, 999)
    # Cap at 200 lines
    assert out.count("\n") <= 200


def test_read_rejects_inverted_range(tmp_path):
    p = tmp_path / "a.py"
    p.write_text("ok\n")
    with pytest.raises(ValueError):
        read_file_range(tmp_path, "a.py", 5, 2)


# ---------------------------------------------------------------------------
# Tool factories (binding to repo_root)
# ---------------------------------------------------------------------------


def test_grep_tool_factory_returns_well_formed_tool(tmp_path):
    tool = make_grep_repo_tool(tmp_path)
    assert tool.name == "grep_repo"
    assert "pattern" in tool.parameters["properties"]
    assert tool.parameters["required"] == ["pattern"]


def test_grep_tool_handler_requires_pattern(tmp_path):
    tool = make_grep_repo_tool(tmp_path)
    assert "pattern is required" in tool.handler({})


def test_read_tool_handler_requires_path(tmp_path):
    tool = make_read_file_range_tool(tmp_path)
    assert "path is required" in tool.handler({"start": 1, "end": 5})


def test_grep_tool_handler_returns_lines(tmp_path):
    _seed_repo(tmp_path)
    tool = make_grep_repo_tool(tmp_path)
    out = tool.handler({"pattern": r"require\('lodash'\)"})
    assert "src/app.js:1:" in out
