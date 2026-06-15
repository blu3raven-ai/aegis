from __future__ import annotations
from src.secrets.scanner import normalize_finding


def _base_trufflehog(**overrides):
    raw = {"source": "trufflehog", "repository": "myorg/myrepo", "DetectorName": "AWSKey", "Redacted": "AKIA***"}
    raw.update(overrides)
    return raw


def test_trufflehog_verified_true_produces_confirmed_entry():
    result = normalize_finding("run1", "myorg", _base_trufflehog(Verified=True), "light")
    history = result["classificationHistory"]
    assert len(history) == 1
    assert history[0]["value"] == "verified_secret"
    assert history[0]["source"] == "scanner"
    assert history[0]["confidence"] == 1.0
    assert history[0]["runId"] == "run1"


def test_trufflehog_verified_false_produces_uncertain_entry():
    result = normalize_finding("run1", "myorg", _base_trufflehog(Verified=False), "deep")
    history = result["classificationHistory"]
    assert len(history) == 1
    assert history[0]["value"] == "uncertain"
    assert history[0]["scanDepth"] == "deep"


def test_trufflehog_verified_missing_produces_uncertain_entry():
    result = normalize_finding("run1", "myorg", _base_trufflehog(), "light")
    history = result["classificationHistory"]
    assert len(history) == 1
    assert history[0]["value"] == "uncertain"


def test_no_verifiedStatus_field_on_finding():
    result = normalize_finding("run1", "myorg", _base_trufflehog(Verified=True), "light")
    assert "verifiedStatus" not in result


def test_no_aiClassification_field_on_finding():
    result = normalize_finding("run1", "myorg", _base_trufflehog(ai_classification="likely_real"), "deep")
    assert "aiClassification" not in result


def test_no_confidence_string_field_on_finding():
    result = normalize_finding("run1", "myorg", _base_trufflehog(Verified=True), "light")
    assert "confidence" not in result


def test_filesystem_mode_extracts_line():
    """TruffleHog filesystem mode puts line under SourceMetadata.Data.Filesystem."""
    raw = {
        "source": "trufflehog",
        "repository": "myorg/myrepo",
        "DetectorName": "AWSKey",
        "Redacted": "AKIA***",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "src/config.py",
                    "line": 42,
                }
            }
        },
    }
    result = normalize_finding("run1", "myorg", raw, "light")
    assert result["line"] == 42


def test_filesystem_mode_extracts_file_path():
    """TruffleHog filesystem mode puts file path under SourceMetadata.Data.Filesystem."""
    raw = {
        "source": "trufflehog",
        "repository": "myorg/myrepo",
        "DetectorName": "AWSKey",
        "Redacted": "AKIA***",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "src/config.py",
                    "line": 42,
                }
            }
        },
    }
    result = normalize_finding("run1", "myorg", raw, "light")
    assert result["filePath"] == "src/config.py"


def test_filesystem_mode_strips_temp_prefix_from_file_path():
    """Trufflehog filesystem mode records absolute container paths — strip /tmp/tmp.*/ prefix."""
    raw = {
        "source": "trufflehog",
        "repository": "myorg/myrepo",
        "DetectorName": "AWSKey",
        "Redacted": "AKIA***",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "/tmp/tmp.7ZoZCpBVex/src/gateway/server.config.ts",
                    "line": 12,
                }
            }
        },
    }
    result = normalize_finding("run1", "myorg", raw, "light")
    assert result["filePath"] == "src/gateway/server.config.ts"


def test_filesystem_mode_commit_is_none():
    """Light scan has no git history — commit must be null."""
    raw = {
        "source": "trufflehog",
        "repository": "myorg/myrepo",
        "DetectorName": "AWSKey",
        "Redacted": "AKIA***",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "src/config.py",
                    "line": 42,
                }
            }
        },
    }
    result = normalize_finding("run1", "myorg", raw, "light")
    assert result["commit"] is None
