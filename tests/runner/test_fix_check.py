"""Positive-only AI-fix apply verification."""
from __future__ import annotations

import tempfile
from pathlib import Path

from runner.verification.enrich import stash_confirmed_enrichment
from runner.verification.fix_check import fix_applies
from runner.verification.schemas.verdict import HunterResponse

_GOOD = (
    "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
    " def f(x):\n-    return eval(x)\n+    return int(x)\n"
)
_BAD = (
    "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n"
    " def g(y):\n-    return danger(y)\n+    return safe(y)\n"
)


def _repo() -> str:
    d = tempfile.mkdtemp()
    (Path(d) / "app.py").write_text("def f(x):\n    return eval(x)\n")
    return d


def test_good_diff_applies():
    assert fix_applies(_GOOD, _repo()) is True


def test_context_mismatch_does_not_apply():
    assert fix_applies(_BAD, _repo()) is False


def test_prose_fix_is_not_a_patch():
    assert fix_applies("Replace eval() with int().", _repo()) is False


def test_empty_returns_false():
    assert fix_applies("", "/tmp") is False


def test_stash_sets_fix_verified_true_for_applying_diff():
    meta: dict = {}
    stash_confirmed_enrichment(meta, HunterResponse(fix=_GOOD), repo_root=_repo())
    assert meta["fix_verified"] is True


def test_stash_sets_fix_verified_false_for_mismatch():
    meta: dict = {}
    stash_confirmed_enrichment(meta, HunterResponse(fix=_BAD), repo_root=_repo())
    assert meta["fix_verified"] is False


def test_stash_without_repo_root_skips_verification():
    meta: dict = {}
    stash_confirmed_enrichment(meta, HunterResponse(fix=_GOOD))
    assert "fix_verified" not in meta
    assert meta["fix"] == _GOOD.strip()
