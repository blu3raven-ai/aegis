"""Tests for SAFE_RELATIVE_PATH regex used by the runner presign endpoints."""
import pytest

from src.shared.paths import SAFE_RELATIVE_PATH


@pytest.mark.parametrize("path", [
    "findings.json",
    "sbom.cdx.json",
    "logs/scan.log",
    "deep/nested/path/file.txt",
    "file_with_under-score.json",
    "file.with.dots.json",
    "_manifest.jsonl",
])
def test_safe_relative_path_accepts_clean_relative_paths(path):
    assert SAFE_RELATIVE_PATH.match(path)


@pytest.mark.parametrize("path", [
    "../etc/passwd",
    "/absolute/path",
    "path/../traversal",
    "path/with spaces.json",
    "path;with;semicolons",
    "path|with|pipes",
    "path\\with\\backslashes",
    "",
    "path/",
    "/file",
])
def test_safe_relative_path_rejects_unsafe_paths(path):
    assert not SAFE_RELATIVE_PATH.match(path)
