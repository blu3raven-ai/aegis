"""Tests for runner.verification.helpers.import_sites."""
from __future__ import annotations

from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mk(repo: Path, rel: str, content: str) -> Path:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# npm / JS / TS detection
# ---------------------------------------------------------------------------


def test_npm_require_match(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/handler.js", "const _ = require('lodash');\nconst x = 1;\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].file == "src/handler.js"
    assert sites[0].line == 1
    assert sites[0].kind == "require"
    assert "require('lodash')" in sites[0].snippet


def test_npm_es_import_match(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/app.ts",
        "import { merge } from 'lodash';\nimport React from 'react';\n",
    )

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].kind == "import"
    assert sites[0].line == 1


def test_npm_subpath_import_match(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/a.js", "const get = require('lodash/get');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert "lodash/get" in sites[0].snippet


def test_npm_dynamic_import(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/lazy.mjs", "const mod = await import('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].kind == "dynamic_import"


def test_npm_no_false_positive_on_substring(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/a.js",
        "const x = require('lodash-es');\nconst y = require('mylodash');\n",
    )

    sites = find_import_sites(tmp_path, "lodash", "npm")
    # "lodash-es" and "mylodash" are different packages — must not match
    assert sites == []


def test_npm_scoped_package(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/a.ts",
        "import { foo } from '@aws-sdk/client-s3';\nconst y = 1;\n",
    )

    sites = find_import_sites(tmp_path, "@aws-sdk/client-s3", "npm")
    assert len(sites) == 1
    assert sites[0].line == 1


def test_npm_export_from(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/reexport.ts", "export { merge } from 'lodash';\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].kind == "import"


# ---------------------------------------------------------------------------
# pip / Python detection
# ---------------------------------------------------------------------------


def test_pip_import_match(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/app.py", "import requests\nfoo = 1\n")

    sites = find_import_sites(tmp_path, "requests", "pypi")
    assert len(sites) == 1
    assert sites[0].kind == "import"
    assert sites[0].line == 1


def test_pip_from_import_match(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/app.py",
        "from requests.adapters import HTTPAdapter\nfrom os import path\n",
    )

    sites = find_import_sites(tmp_path, "requests", "pypi")
    assert len(sites) == 1
    assert sites[0].kind == "from_import"


def test_pip_dash_to_underscore_alias(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    # pip pkg "python-dateutil" is imported as "dateutil" or "python_dateutil"
    _mk(tmp_path, "src/a.py", "import python_dateutil\n")

    sites = find_import_sites(tmp_path, "python-dateutil", "pypi")
    assert len(sites) == 1


def test_pip_no_false_positive_on_substring(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/a.py",
        "import myrequests\nfrom requestsx import foo\nimport requests_oauth\n",
    )

    sites = find_import_sites(tmp_path, "requests", "pypi")
    # None of these are the real "requests" package
    assert sites == []


def test_pip_with_alias(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/a.py", "import requests as r\nimport os\n")

    sites = find_import_sites(tmp_path, "requests", "pypi")
    assert len(sites) == 1


# ---------------------------------------------------------------------------
# Caps + context
# ---------------------------------------------------------------------------


def test_max_sites_cap_respected(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    for i in range(8):
        _mk(tmp_path / "src", f"f{i}.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm", max_sites=3)
    assert len(sites) == 3


def test_context_lines_in_snippet(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(
        tmp_path,
        "src/a.js",
        "// header comment\n"
        "// another\n"
        "const _ = require('lodash');\n"
        "const next = 1;\n"
        "const more = 2;\n",
    )

    sites = find_import_sites(
        tmp_path, "lodash", "npm", context_lines=1
    )
    assert len(sites) == 1
    snippet = sites[0].snippet
    # ±1 line around line 3
    assert "// another" in snippet
    assert "require('lodash')" in snippet
    assert "const next = 1;" in snippet
    assert "// header comment" not in snippet
    assert "const more = 2;" not in snippet


# ---------------------------------------------------------------------------
# Sandboxing / excluded dirs
# ---------------------------------------------------------------------------


def test_excluded_dirs_skipped(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path / "node_modules" / "lodash", "index.js", "require('lodash');\n")
    _mk(tmp_path / ".git", "hooks.js", "require('lodash');\n")
    _mk(tmp_path / "dist", "bundle.js", "require('lodash');\n")
    _mk(tmp_path / "__pycache__", "x.py", "import requests\n")
    _mk(tmp_path / "src", "app.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].file == "src/app.js"


def test_extra_excluded_dirs(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path / "scripts", "build.js", "require('lodash');\n")
    _mk(tmp_path / "src", "app.js", "require('lodash');\n")

    sites = find_import_sites(
        tmp_path, "lodash", "npm", extra_excluded_dirs=("scripts",)
    )
    assert len(sites) == 1
    assert sites[0].file == "src/app.js"


def test_binary_files_skipped(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    # File with .js extension but binary content shouldn't crash
    binary = tmp_path / "src" / "bin.js"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"\x00\x01\x02require('lodash')\x03\x04")

    _mk(tmp_path / "src", "real.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    # Only the real source file should match
    assert len(sites) == 1
    assert sites[0].file == "src/real.js"


def test_large_files_skipped(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    big = tmp_path / "src" / "big.js"
    big.parent.mkdir(parents=True)
    # 1.5MB of junk plus an import line — should be skipped
    big.write_text("x" * 1_500_000 + "\nrequire('lodash');\n")
    _mk(tmp_path / "src", "small.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert len(sites) == 1
    assert sites[0].file == "src/small.js"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_unknown_ecosystem_returns_empty(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/a.go", 'import "lodash"\n')

    sites = find_import_sites(tmp_path, "lodash", "go")
    assert sites == []


def test_nonexistent_repo_returns_empty(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    sites = find_import_sites(tmp_path / "does-not-exist", "lodash", "npm")
    assert sites == []


def test_empty_package_name_returns_empty(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path, "src/a.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "", "npm")
    assert sites == []


def test_returns_repo_relative_posix_paths(tmp_path):
    from runner.verification.helpers.import_sites import find_import_sites

    _mk(tmp_path / "src" / "deeply" / "nested", "mod.js", "require('lodash');\n")

    sites = find_import_sites(tmp_path, "lodash", "npm")
    assert sites[0].file == "src/deeply/nested/mod.js"


def test_to_dict_round_trip():
    from runner.verification.helpers.import_sites import ImportSite

    s = ImportSite(file="a/b.js", line=4, snippet="x\ny", kind="require")
    assert s.to_dict() == {
        "file": "a/b.js",
        "line": 4,
        "snippet": "x\ny",
        "kind": "require",
    }
