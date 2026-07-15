"""find_import_sites is the dependency-reachability parser behind verify_deps_finding
(verifiers/deps.py). One check per ecosystem branch that fails if the matcher breaks."""
from __future__ import annotations

from pathlib import Path

from runner.verification.helpers.import_sites import find_import_sites


def _repo(tmp_path: Path, name: str, body: str) -> Path:
    (tmp_path / name).write_text(body)
    return tmp_path


def test_python_from_import_is_found(tmp_path):
    repo = _repo(tmp_path, "app.py", "import os\nfrom requests import get\n")
    sites = find_import_sites(repo, "requests", "pypi")
    assert len(sites) == 1
    assert sites[0].file == "app.py" and sites[0].line == 2 and sites[0].kind == "from_import"


def test_javascript_require_and_import(tmp_path):
    repo = _repo(tmp_path, "a.js", "const _ = require('lodash')\nimport x from 'lodash/get'\n")
    kinds = {s.kind for s in find_import_sites(repo, "lodash", "npm")}
    assert kinds == {"require", "import"}


def test_unsupported_ecosystem_returns_empty(tmp_path):
    repo = _repo(tmp_path, "app.py", "from requests import get\n")
    assert find_import_sites(repo, "requests", "maven") == []


def test_max_sites_caps_results(tmp_path):
    body = "".join(f"from requests import get  # {i}\n" for i in range(10))
    repo = _repo(tmp_path, "app.py", body)
    assert len(find_import_sites(repo, "requests", "pypi", max_sites=3)) == 3
