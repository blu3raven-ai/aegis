from __future__ import annotations
from src.secrets.scanner import build_classification_entries


def test_trufflehog_verified_true_produces_verified_secret():
    raw = {"source": "trufflehog", "Verified": True}
    entries = build_classification_entries(raw, "run1", "light", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "verified_secret"
    assert entries[0]["source"] == "scanner"
    assert entries[0]["confidence"] == 1.0
    assert entries[0]["scanDepth"] == "light"
    assert entries[0]["runId"] == "run1"


def test_trufflehog_verified_false_produces_uncertain_with_null_confidence():
    raw = {"source": "trufflehog", "Verified": False}
    entries = build_classification_entries(raw, "run1", "deep", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "uncertain"
    assert entries[0]["confidence"] is None
    assert entries[0]["source"] == "scanner"


def test_trufflehog_verified_missing_produces_uncertain():
    raw = {"source": "trufflehog"}
    entries = build_classification_entries(raw, "run1", "light", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "uncertain"
    assert entries[0]["confidence"] is None


def test_betterleaks_produces_no_scanner_entry():
    raw = {"source": "betterleaks", "Secret": "abc123"}
    entries = build_classification_entries(raw, "run1", "light", "2026-04-27T00:00:00Z")
    assert entries == []


def test_betterleaks_likely_real_produces_likely_secret():
    raw = {"source": "betterleaks", "ai_classification": "likely_real"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "likely_secret"
    assert entries[0]["source"] == "ai"
    assert entries[0]["confidence"] == 0.80


def test_betterleaks_uncertain_produces_uncertain_with_null_confidence():
    raw = {"source": "betterleaks", "ai_classification": "uncertain"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "uncertain"
    assert entries[0]["confidence"] is None
    assert entries[0]["source"] == "ai"


def test_betterleaks_likely_false_positive_produces_not_secret():
    raw = {"source": "betterleaks", "ai_classification": "likely_false_positive"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "not_secret"
    assert entries[0]["confidence"] == 0.80
    assert entries[0]["source"] == "ai"


def test_betterleaks_false_positive_produces_not_secret():
    raw = {"source": "betterleaks", "ai_classification": "false_positive"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert entries[0]["value"] == "not_secret"
    assert entries[0]["confidence"] == 0.80


def test_trufflehog_verified_with_ai_classification_produces_two_entries():
    raw = {"source": "trufflehog", "Verified": True, "ai_classification": "likely_real"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert len(entries) == 2
    assert entries[0]["source"] == "scanner"
    assert entries[0]["value"] == "verified_secret"
    assert entries[0]["confidence"] == 1.0
    assert entries[1]["source"] == "ai"
    assert entries[1]["value"] == "likely_secret"
    assert entries[1]["confidence"] == 0.80


def test_invalid_ai_classification_is_ignored():
    raw = {"source": "betterleaks", "ai_classification": "maybe_bad"}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert entries == []


def test_scan_depth_none_stored_as_none():
    raw = {"source": "trufflehog", "Verified": True}
    entries = build_classification_entries(raw, "run1", None, "2026-04-27T00:00:00Z")
    assert entries[0]["scanDepth"] is None


def test_betterleaks_ai_confidence_passthrough():
    """Real model confidence score from ai_confidence field passes through correctly."""
    raw = {"source": "betterleaks", "ai_classification": "likely_real", "ai_confidence": 0.9347}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert len(entries) == 1
    assert entries[0]["value"] == "likely_secret"
    assert entries[0]["confidence"] == 0.9347


def test_betterleaks_out_of_range_confidence_falls_back():
    """ai_confidence outside [0.0, 1.0] falls back to the default 0.80."""
    raw = {"source": "betterleaks", "ai_classification": "likely_real", "ai_confidence": 1.5}
    entries = build_classification_entries(raw, "run1", "ai_enhanced", "2026-04-27T00:00:00Z")
    assert entries[0]["confidence"] == 0.80


def test_ingest_findings_passes_scan_depth_to_entries(monkeypatch):
    """scan_depth=ai_enhanced must propagate into classificationHistory entries."""
    from src.secrets import scanner

    raw = {
        "source": "trufflehog",
        "repository": "myorg/myrepo",
        "DetectorName": "AWSKey",
        "Redacted": "AKIA***",
        "Verified": True,
    }

    captured = []
    def capture_merge(current, prev):
        captured.extend(current)
        return current

    monkeypatch.setattr(scanner, "read_latest_findings", lambda org: [])
    monkeypatch.setattr(scanner, "merge_pool", capture_merge)
    monkeypatch.setattr(scanner, "_apply_lifecycle", lambda hooks, ctx, findings: [])

    scanner.ingest_findings("myorg", "run-depth", [raw], scan_depth="ai_enhanced")

    finding = captured[0]
    assert finding["classificationHistory"][0]["scanDepth"] == "ai_enhanced"
