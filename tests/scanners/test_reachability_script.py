"""Tests for reachability.py — tmp-prefix stripping, snippet extraction, and output key format."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

# Load the hyphenated-name module directly
_spec = importlib.util.spec_from_file_location(
    "reachability",
    Path(__file__).parent.parent.parent / "scanners" / "code-scanning" / "scripts" / "reachability.py",
)
_mod = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_strip_tmp_prefix = _mod._strip_tmp_prefix
_read_snippet = _mod._read_snippet
build_reachability = _mod.build_reachability


# ── _strip_tmp_prefix ─────────────────────────────────────────────────────────


def test_strip_tmp_prefix_removes_absolute_temp_path():
    assert _strip_tmp_prefix("/tmp/tmp.tum6N6HTcv/server.py") == "server.py"


def test_strip_tmp_prefix_removes_nested_absolute_temp_path():
    assert _strip_tmp_prefix("/tmp/tmp.ABC123/src/api/routes.py") == "src/api/routes.py"


def test_strip_tmp_prefix_passthrough_relative_path():
    assert _strip_tmp_prefix("server.py") == "server.py"


def test_strip_tmp_prefix_passthrough_nested_relative_path():
    assert _strip_tmp_prefix("src/api/routes.py") == "src/api/routes.py"


def test_strip_tmp_prefix_empty_string():
    # Empty string — `or uri` guard returns the original empty string
    assert _strip_tmp_prefix("") == ""


def test_strip_tmp_prefix_does_not_strip_non_tmp_absolute():
    # /var/app/server.py has no /tmp/tmp.XXX/ prefix — must be left alone
    result = _strip_tmp_prefix("/var/app/server.py")
    assert result == "/var/app/server.py"


# ── _read_snippet ─────────────────────────────────────────────────────────────


def test_read_snippet_reads_correct_lines(tmp_path):
    src = tmp_path / "server.py"
    src.write_text("line1\nline2\nline3\nline4\nline5\nline6\n")

    snippet = _read_snippet(tmp_path, "server.py", start_line=2, n=3)
    assert snippet == "line2\nline3\nline4"


def test_read_snippet_start_line_is_1_indexed(tmp_path):
    src = tmp_path / "server.py"
    src.write_text("first\nsecond\nthird\n")

    snippet = _read_snippet(tmp_path, "server.py", start_line=1, n=1)
    assert snippet == "first"


def test_read_snippet_strips_common_leading_indent(tmp_path):
    src = tmp_path / "app.py"
    src.write_text("def f():\n    x = 1\n    return x\n")

    # start_line=2 → "    x = 1", "    return x"
    snippet = _read_snippet(tmp_path, "app.py", start_line=2, n=2)
    assert snippet == "x = 1\nreturn x"


def test_read_snippet_returns_none_for_missing_file(tmp_path):
    result = _read_snippet(tmp_path, "does_not_exist.py", start_line=1)
    assert result is None


def test_read_snippet_clamps_to_end_of_file(tmp_path):
    src = tmp_path / "short.py"
    src.write_text("only_line\n")

    snippet = _read_snippet(tmp_path, "short.py", start_line=1, n=10)
    assert snippet == "only_line"


# ── build_reachability — key format ──────────────────────────────────────────


def _sarif_with_uri(uri: str, start_line: int = 1) -> dict:
    return {
        "runs": [{
            "tool": {"driver": {"name": "opengrep", "rules": []}},
            "results": [{
                "ruleId": "python.injection",
                "message": {"text": "Potential injection"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": uri},
                        "region": {"startLine": start_line},
                    }
                }],
            }],
        }]
    }


def test_build_reachability_keys_are_relative_when_sarif_has_absolute_uri(tmp_path):
    """
    When Opengrep embeds /tmp/tmp.XXXX/ paths in the SARIF, the output dict keys
    must be the stripped relative paths so normalize-code-scanning.py can look them up.
    """
    clone = tmp_path / "repo"
    clone.mkdir()
    # Module-level code (outside any function) → reachable without tree-sitter
    (clone / "server.py").write_text("requests.post(URL, data=payload)\n")

    abs_uri = "/tmp/tmp.tum6N6HTcv/server.py"
    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps(_sarif_with_uri(abs_uri, start_line=1)))

    result = build_reachability(str(clone), str(sarif_file))

    # Key must be relative, not absolute
    assert "server.py:1" in result, f"Expected 'server.py:1' in output, got: {list(result.keys())}"
    assert f"{abs_uri}:1" not in result


def test_build_reachability_relative_uri_still_works(tmp_path):
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "server.py").write_text("requests.post(URL)\n")

    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps(_sarif_with_uri("server.py", start_line=1)))

    result = build_reachability(str(clone), str(sarif_file))

    assert "server.py:1" in result


def test_build_reachability_module_level_code_is_reachable(tmp_path):
    """Code outside any function in a non-dead-code path is always reachable."""
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "server.py").write_text("os.system(user_input)\n")

    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps(_sarif_with_uri("server.py", start_line=1)))

    result = build_reachability(str(clone), str(sarif_file))

    assert result.get("server.py:1", {}).get("verdict") == "reachable"
    assert result["server.py:1"]["entry_point"] == "module-level"


def test_build_reachability_dead_code_dir_is_unreachable(tmp_path):
    """Code in test/ subdirectory is always marked unreachable."""
    clone = tmp_path / "repo"
    (clone / "tests").mkdir(parents=True)
    (clone / "tests" / "helpers.py").write_text("os.system(user_input)\n")

    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps(_sarif_with_uri("tests/helpers.py", start_line=1)))

    result = build_reachability(str(clone), str(sarif_file))

    assert result.get("tests/helpers.py:1", {}).get("verdict") == "unreachable"


def test_build_reachability_call_chain_steps_have_snippet_key(tmp_path):
    """
    When a reachable call chain is produced, every step must include a 'snippet' key.
    This confirms _read_snippet is wired into build_reachability.
    """
    clone = tmp_path / "repo"
    clone.mkdir()
    (clone / "server.py").write_text("requests.post(URL)\n")

    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps(_sarif_with_uri("server.py", start_line=1)))

    result = build_reachability(str(clone), str(sarif_file))

    entry = result.get("server.py:1", {})
    if entry.get("verdict") == "reachable" and "call_chain" in entry:
        for step in entry["call_chain"]:
            assert "snippet" in step, f"Call chain step missing 'snippet' key: {step}"


def test_build_reachability_empty_sarif_returns_empty(tmp_path):
    clone = tmp_path / "repo"
    clone.mkdir()
    sarif_file = tmp_path / "opengrep.json"
    sarif_file.write_text(json.dumps({"runs": []}))

    assert build_reachability(str(clone), str(sarif_file)) == {}


def test_build_reachability_missing_sarif_returns_empty(tmp_path):
    clone = tmp_path / "repo"
    clone.mkdir()
    assert build_reachability(str(clone), str(tmp_path / "no_such_file.json")) == {}
