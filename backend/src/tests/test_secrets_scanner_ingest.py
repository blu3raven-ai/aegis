"""Regression tests for the TruffleHog-to-canonical bridge in secrets ingest.

The runner emits raw TruffleHog records (top-level ``Raw`` / ``DetectorName``
/ ``SourceMetadata``) with only ``source`` and ``repository`` tags added. The
backend ingest path must wrap these into the canonical shape so
``ensure_secret_identity`` can compute a non-empty key — otherwise
``merge_pool`` silently drops every finding.
"""
from __future__ import annotations

from src.secrets.scanner import _adapt_trufflehog_to_canonical
from src.secrets.store import ensure_secret_identity
from src.secrets.pool import merge_pool


def _runner_emitted_trufflehog_record() -> dict:
    """A representative record matching what runner/scanners/secrets/normalize.py emits.

    The runner copies TruffleHog's JSONL line verbatim and only tags it with
    ``source`` + ``repository``. TruffleHog itself emits the fields below at
    the top level.
    """
    return {
        "SourceMetadata": {
            "Data": {
                "Git": {
                    "commit": "abc123def456",
                    "file": "src/config/secrets.py",
                    "line": 42,
                    "timestamp": "2026-06-15T10:00:00Z",
                    "repository": "https://github.com/example-org/example-repo",
                }
            }
        },
        "SourceID": 1,
        "SourceType": 16,
        "SourceName": "trufflehog - git",
        "DetectorType": 17,
        "DetectorName": "AWS",
        "DecoderName": "PLAIN",
        "Verified": False,
        "Raw": "AKIAIOSFODNN7EXAMPLE",
        "RawV2": "AKIAIOSFODNN7EXAMPLE-secret-key",
        "Redacted": "AKIA***********PLE",
        "source": "trufflehog",
        "repository": "example-org/example-repo",
    }


def test_adapter_produces_non_empty_secret_identity():
    record = _runner_emitted_trufflehog_record()
    adapted = _adapt_trufflehog_to_canonical(record, org="acme-org")
    enriched = ensure_secret_identity(adapted)
    assert enriched["secretIdentity"], (
        "Bridging shim must populate the canonical fields so "
        "ensure_secret_identity returns a non-empty SHA — without it the "
        "finding is silently dropped by merge_pool."
    )


def test_adapter_preserves_runner_tags():
    record = _runner_emitted_trufflehog_record()
    adapted = _adapt_trufflehog_to_canonical(record, org="acme-org")
    assert adapted["source"] == "trufflehog"
    assert adapted["repository"] == "example-org/example-repo"


def test_adapter_extracts_locations_for_downstream():
    record = _runner_emitted_trufflehog_record()
    adapted = _adapt_trufflehog_to_canonical(record, org="acme-org")
    assert adapted["filePath"] == "src/config/secrets.py"
    assert adapted["line"] == 42
    assert adapted["commit"] == "abc123def456"
    assert adapted["detector"] == "AWS"
    assert adapted["organization"] == "acme-org"


def test_adapter_is_idempotent_on_canonical_input():
    canonical = {
        "organization": "acme-org",
        "raw": {"Secret": "abc", "Match": "abc", "Redacted": "abc"},
        "secretSnippet": "abc",
        "repository": "repo-x",
        "filePath": "f.py",
        "line": 1,
        "commit": "deadbeef",
        "detectedAt": "2026-06-15T00:00:00Z",
        "detector": "Test",
        "source": "trufflehog",
    }
    result = _adapt_trufflehog_to_canonical(canonical, org="ignored")
    assert result is canonical


def test_bridged_record_survives_merge_pool():
    """End-to-end pure-function check: bridge -> identity -> merge_pool.

    Without the bridge, ``merge_pool`` sees ``secretIdentity = None`` and
    ``build_secret_identity`` returns ``None`` (no ``organization``, no
    ``raw.Secret``), so the finding is silently skipped by the
    ``if not identity: continue`` guard.
    """
    record = _runner_emitted_trufflehog_record()
    adapted = _adapt_trufflehog_to_canonical(record, org="acme-org")
    enriched = ensure_secret_identity(adapted)

    merged = merge_pool([enriched], previous_findings=[])

    assert len(merged) == 1, "Bridged finding must not be dropped by merge_pool"
    assert merged[0]["secretIdentity"] == enriched["secretIdentity"]
    assert merged[0]["locations"], "merge_pool should populate a non-empty locations list"
