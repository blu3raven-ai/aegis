"""Tests for runner.verification.pipelines.dedupe.deduplicate_findings."""
from __future__ import annotations

import pytest

from runner.verification.pipelines.dedupe import (
    compute_dedup_key,
    deduplicate_findings,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sca(
    *,
    id="s1",
    advisory="CVE-2021-23337",
    pkg="lodash",
    version="4.17.20",
    severity="high",
    manifestPath="/package.json",
) -> dict:
    return {
        "id": id,
        "scanner": "dependencies_scanning",
        "advisoryId": advisory,
        "packageName": pkg,
        "packageVersion": version,
        "severity": severity,
        "manifestPath": manifestPath,
    }


def _secret(
    *,
    id="x1",
    detector="aws-secret-key",
    redacted="AKIAxxxxxx",
    file="cfg.env",
    line=2,
    severity="high",
) -> dict:
    return {
        "id": id,
        "scanner": "secret_scanning",
        "detectorName": detector,
        "redactedMatch": redacted,
        "file": file,
        "line": line,
        "severity": severity,
    }


def _sast(
    *,
    id="c1",
    rule="ssrf-request",
    file="src/api.py",
    line=47,
    severity="high",
) -> dict:
    return {
        "id": id,
        "scanner": "code-scanning",
        "rule": rule,
        "file": file,
        "line": line,
        "severity": severity,
    }


def _container(
    *,
    id="k1",
    advisory="CVE-2024-1",
    pkg="openssl",
    version="1.1.1k",
    digest="sha256:abc",
    severity="critical",
) -> dict:
    return {
        "id": id,
        "scanner": "container",
        "advisoryId": advisory,
        "packageName": pkg,
        "packageVersion": version,
        "imageDigest": digest,
        "severity": severity,
    }


# ---------------------------------------------------------------------------
# Dedup keys
# ---------------------------------------------------------------------------


def test_sca_key_uses_advisory_package_version():
    assert compute_dedup_key(_sca()) == compute_dedup_key(_sca(id="other"))


def test_sca_different_version_not_duplicate():
    assert compute_dedup_key(_sca(version="4.17.20")) != compute_dedup_key(_sca(version="4.17.21"))


def test_sca_missing_advisory_returns_none():
    assert compute_dedup_key(_sca(advisory="")) is None


def test_secret_key_uses_redacted_match_and_detector():
    assert compute_dedup_key(_secret()) == compute_dedup_key(_secret(id="other", file="other.env"))


def test_secret_different_redacted_match_not_duplicate():
    assert compute_dedup_key(_secret(redacted="AAA")) != compute_dedup_key(_secret(redacted="BBB"))


def test_sast_key_uses_rule_file_line():
    assert compute_dedup_key(_sast()) == compute_dedup_key(_sast(id="other"))


def test_sast_different_line_not_duplicate():
    assert compute_dedup_key(_sast(line=10)) != compute_dedup_key(_sast(line=20))


def test_container_key_includes_image_digest():
    a = _container(digest="sha256:img-a")
    b = _container(digest="sha256:img-b")
    assert compute_dedup_key(a) != compute_dedup_key(b)


def test_unknown_scanner_returns_none_key():
    assert compute_dedup_key({"id": "x", "scanner": "unknown_thing"}) is None


# ---------------------------------------------------------------------------
# Dedup behavior
# ---------------------------------------------------------------------------


def test_no_duplicates_returns_findings_unchanged():
    findings = [_sca(id="a"), _secret(id="b"), _sast(id="c")]
    result = deduplicate_findings(findings)
    assert result.merged_count == 0
    assert result.duplicate_groups == 0
    assert len(result.primaries) == 3


def test_sca_duplicates_collapsed_to_one_primary():
    a = _sca(id="a", manifestPath="/services/api/package.json")
    b = _sca(id="b", manifestPath="/services/web/package.json")
    c = _sca(id="c", manifestPath="/package.json")
    result = deduplicate_findings([a, b, c])
    assert result.merged_count == 2
    assert result.duplicate_groups == 1
    assert len(result.primaries) == 1
    primary = result.primaries[0]
    assert primary["duplicate_count"] == 3
    assert set(primary["duplicate_finding_ids"]) == {"b", "c"}


def test_dup_sources_record_every_location():
    a = _sca(id="a", manifestPath="/services/api/package.json")
    b = _sca(id="b", manifestPath="/services/web/package.json")
    result = deduplicate_findings([a, b])
    primary = result.primaries[0]
    paths = {s["file"] for s in primary["duplicate_sources"]}
    assert paths == {"/services/api/package.json", "/services/web/package.json"}


def test_primary_picked_by_highest_severity():
    low = _sca(id="low", severity="medium")
    high = _sca(id="high", severity="critical")
    medium = _sca(id="medium", severity="low")
    result = deduplicate_findings([low, high, medium])
    assert result.primaries[0]["id"] == "high"


def test_primary_tiebreak_by_lowest_id():
    a = _sca(id="zzz", severity="high")
    b = _sca(id="aaa", severity="high")
    result = deduplicate_findings([a, b])
    assert result.primaries[0]["id"] == "aaa"


def test_keyless_findings_pass_through():
    findings = [_sca(id="real"), {"id": "unknown", "scanner": "mystery"}]
    result = deduplicate_findings(findings)
    ids = {p["id"] for p in result.primaries}
    assert ids == {"real", "unknown"}


def test_secret_dedup_across_files():
    a = _secret(id="s1", file="cfg.env")
    b = _secret(id="s2", file="docker/.env")
    result = deduplicate_findings([a, b])
    assert result.merged_count == 1
    primary = result.primaries[0]
    files = {s["file"] for s in primary["duplicate_sources"]}
    assert files == {"cfg.env", "docker/.env"}


def test_sast_dedup_same_file_line_different_id():
    a = _sast(id="a")
    b = _sast(id="b")
    result = deduplicate_findings([a, b])
    assert result.merged_count == 1
    assert len(result.primaries) == 1


def test_container_per_image_kept_separate():
    a = _container(id="ka", digest="sha256:1")
    b = _container(id="kb", digest="sha256:2")
    result = deduplicate_findings([a, b])
    assert result.merged_count == 0
    assert len(result.primaries) == 2


def test_mixed_scanner_groups_independent():
    findings = [
        _sca(id="dep1"),
        _sca(id="dep2"),
        _secret(id="sec1"),
        _secret(id="sec2"),
        _sast(id="sast1"),
    ]
    result = deduplicate_findings(findings)
    # Two dedup groups (sca + secrets), one unduplicated sast
    assert result.duplicate_groups == 2
    assert result.merged_count == 2
    assert len(result.primaries) == 3


def test_empty_input_returns_empty_result():
    result = deduplicate_findings([])
    assert result.primaries == []
    assert result.merged_count == 0
    assert result.duplicate_groups == 0
