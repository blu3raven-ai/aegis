"""Repo sources must not dispatch container scanning.

Container scanning targets images (it needs image refs a repo job never
supplies), so it belongs only to image sources. A repo scan that spawned a
container job produced a no-op job and a dangling ScanRun.
"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://test:test@localhost:5432/test")
os.environ.setdefault("RUNNER_ENCRYPTION_KEY", "0" * 64)

import pytest  # noqa: E402

from src.scans.service import (  # noqa: E402
    _DEFAULT_SCANNERS,
    ScannerNotApplicableError,
    _validate_scanners_for_asset_type,
)


def test_container_not_applicable_to_repo():
    with pytest.raises(ScannerNotApplicableError):
        _validate_scanners_for_asset_type("repo", ["container_scanning"])


def test_repo_default_scanners_exclude_container():
    assert "container_scanning" not in _DEFAULT_SCANNERS
    # the three repo scanners plus IaC remain
    assert set(_DEFAULT_SCANNERS) == {
        "dependencies_scanning",
        "code_scanning",
        "secret_scanning",
        "iac_scanning",
    }


def test_repo_scanners_still_valid():
    # the legitimate repo scanners must still pass validation
    _validate_scanners_for_asset_type(
        "repo", ["dependencies_scanning", "code_scanning", "secret_scanning", "iac_scanning"]
    )


def test_container_still_valid_for_image():
    _validate_scanners_for_asset_type("image", ["container_scanning"])
