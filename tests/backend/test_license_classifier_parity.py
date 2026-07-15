"""Parity guard: the backend license classifier must agree with the shared
fixture set that the frontend mirror (frontend/lib/sbom/license-category.ts) is
also asserted against (tests/frontend/license-category-parity.test.ts). If either
classifier drifts, its own test fails — so the per-repo client-parsed table and
the estate explorer can't silently classify the same component differently."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.sbom.licenses import classify_licenses

# repo_root/tests/backend/this.py -> parents[2] == repo root
_FIXTURES = Path(__file__).parents[2] / "tests" / "fixtures" / "license-classification.json"


def _load() -> list[dict]:
    return json.loads(_FIXTURES.read_text())


def test_fixture_file_exists_and_is_shared():
    assert _FIXTURES.exists(), f"shared fixture missing at {_FIXTURES}"
    assert len(_load()) >= 20


@pytest.mark.parametrize("fx", _load(), ids=lambda fx: fx["desc"])
def test_backend_classifier_matches_shared_fixture(fx):
    assert classify_licenses(fx["licenses"]).category == fx["category"], (
        f"backend classifier drifted on: {fx['desc']} ({fx['licenses']})"
    )
