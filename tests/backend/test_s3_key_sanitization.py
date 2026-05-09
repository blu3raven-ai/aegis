"""Tests for S3 key sanitization — prevent path traversal."""
from src.shared.sbom_storage import safe_s3_segment as _safe_s3_segment


def test_safe_segment_strips_traversal():
    assert ".." not in _safe_s3_segment("../../../etc")


def test_safe_segment_strips_null_bytes():
    assert "\x00" not in _safe_s3_segment("org\x00/repo")


def test_safe_segment_strips_leading_trailing_slashes():
    result = _safe_s3_segment("/org/repo/")
    assert not result.startswith("/")
    assert not result.endswith("/")


def test_safe_segment_preserves_normal_input():
    assert _safe_s3_segment("acme-org") == "acme-org"


def test_safe_segment_preserves_org_repo_slash():
    result = _safe_s3_segment("acme-org/my-repo")
    assert "acme-org" in result
    assert "my-repo" in result
