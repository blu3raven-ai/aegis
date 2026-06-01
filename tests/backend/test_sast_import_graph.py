"""Tests for parse_imports in import_graph.py."""
from __future__ import annotations

from pathlib import Path

import pytest

from src.code_scanning.import_graph import parse_imports


# ── Python import parsing ─────────────────────────────────────────────────────


def test_python_simple_import():
    result = parse_imports(Path("app.py"), "import os\nimport sys\n")
    assert "os" in result
    assert "sys" in result


def test_python_from_import():
    result = parse_imports(Path("app.py"), "from pathlib import Path\n")
    assert "pathlib" in result


def test_python_from_import_with_alias():
    result = parse_imports(Path("app.py"), "from collections import OrderedDict as OD\n")
    assert "collections" in result


def test_python_import_alias():
    result = parse_imports(Path("app.py"), "import numpy as np\n")
    assert "numpy" in result


def test_python_relative_import():
    result = parse_imports(Path("pkg/app.py"), "from .utils import helper\n")
    assert ".utils" in result


def test_python_double_dot_relative_import():
    result = parse_imports(Path("pkg/sub/app.py"), "from ..models import User\n")
    assert "..models" in result


def test_python_multi_import():
    result = parse_imports(Path("app.py"), "import os, sys, re\n")
    assert "os" in result
    assert "sys" in result
    assert "re" in result


def test_python_dotted_module_truncated_to_top_level():
    # 'from a.b.c import X' → specifier is 'a' (top-level package)
    result = parse_imports(Path("app.py"), "from a.b.c import X\n")
    assert "a" in result


def test_python_empty_file():
    assert parse_imports(Path("app.py"), "") == []


def test_python_no_imports():
    assert parse_imports(Path("app.py"), "x = 1\nprint(x)\n") == []


# ── JS/TS import parsing ──────────────────────────────────────────────────────


def test_js_default_import():
    result = parse_imports(Path("index.js"), "import React from 'react';\n")
    assert "react" in result


def test_js_named_import():
    result = parse_imports(Path("index.js"), "import { useState } from 'react';\n")
    assert "react" in result


def test_js_relative_import():
    result = parse_imports(Path("src/index.js"), "import utils from './utils';\n")
    assert "./utils" in result


def test_ts_import():
    result = parse_imports(Path("app.ts"), "import { Foo } from '../lib/foo';\n")
    assert "../lib/foo" in result


def test_tsx_import():
    result = parse_imports(Path("component.tsx"), "import Button from './Button';\n")
    assert "./Button" in result


def test_js_require():
    result = parse_imports(Path("server.js"), "const express = require('express');\n")
    assert "express" in result


def test_js_require_relative():
    result = parse_imports(Path("app.js"), "const utils = require('./utils');\n")
    assert "./utils" in result


def test_mjs_import():
    result = parse_imports(Path("mod.mjs"), "import { x } from './x.js';\n")
    assert "./x.js" in result


def test_js_no_imports():
    assert parse_imports(Path("app.js"), "const x = 1;\n") == []


# ── Unsupported languages ─────────────────────────────────────────────────────


def test_unsupported_language_returns_empty():
    result = parse_imports(Path("main.go"), "import \"fmt\"\n")
    assert result == []


def test_ruby_returns_empty():
    result = parse_imports(Path("app.rb"), "require 'rails'\n")
    assert result == []


def test_no_extension_returns_empty():
    result = parse_imports(Path("Makefile"), "include common.mk\n")
    assert result == []


# ── Malformed / edge cases ────────────────────────────────────────────────────


def test_python_malformed_does_not_raise():
    # Should not raise; just return whatever could be parsed
    content = "from import \nimport \nfrom . import\n"
    result = parse_imports(Path("app.py"), content)
    assert isinstance(result, list)


def test_js_malformed_does_not_raise():
    content = "import from ;\nrequire();\n"
    result = parse_imports(Path("app.js"), content)
    assert isinstance(result, list)


def test_python_comments_not_parsed_as_imports():
    content = "# import os\n# from sys import path\nx = 1\n"
    result = parse_imports(Path("app.py"), content)
    assert result == []
