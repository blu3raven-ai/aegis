"""cdxgen must run with --no-install-deps so it never executes the scanned
repo's setup.py / build hooks on the runner host (scanner-output RCE)."""
from __future__ import annotations

import threading
from pathlib import Path
from unittest.mock import patch

import pytest


def test_cdxgen_invocation_disables_dependency_installation(tmp_path):
    captured: dict = {}
    output = tmp_path / "sbom.json"

    def _fake_run_tool(args, **kwargs):
        captured["args"] = list(args)
        output.write_text("{}")  # simulate cdxgen writing the SBOM
        return 0, "", ""

    from runner.scanners.dependencies import scanner as deps_scanner

    instance = deps_scanner.DependenciesScanner.__new__(deps_scanner.DependenciesScanner)
    with patch.object(deps_scanner, "shutil") as shutil, \
         patch.object(deps_scanner, "run_tool", side_effect=_fake_run_tool):
        shutil.which.return_value = "/usr/local/bin/cdxgen"
        ok = instance._run_cdxgen(tmp_path, output, threading.Event())

    assert ok is True
    argv = captured["args"]
    assert argv[0] == "cdxgen"
    assert "--no-install-deps" in argv, "cdxgen must not install deps (would execute untrusted setup.py)"
