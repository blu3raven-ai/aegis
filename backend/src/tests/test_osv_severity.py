"""OSV severity derivation — CVSS-vector fallback for non-npm advisories.

Regression guard: dependency/container findings from PyPI, CVE-native, and
distro advisories carry severity only as a CVSS vector (no
``database_specific.severity``) and used to persist as ``"unknown"``.
"""
from src.osv.severity import (
    base_score_from_vector,
    severity_word_from_osv_body,
)
from src.osv.sca_findings import _severity_level
from src.osv.store import _derive_severity

# Verified base scores: v3 → 9.8, v2 → 7.5, v4 → 9.3.
_V3_CRITICAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_V2_HIGH = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
_V4_CRITICAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def test_database_specific_word_wins():
    body = {"database_specific": {"severity": "MODERATE"}}
    assert severity_word_from_osv_body(body) == "medium"


def test_cvss_v3_vector_maps_when_no_database_specific():
    body = {"severity": [{"type": "CVSS_V3", "score": _V3_CRITICAL}]}
    assert severity_word_from_osv_body(body) == "critical"


def test_cvss_v2_vector_maps_via_v3_bands():
    body = {"severity": [{"type": "CVSS_V2", "score": _V2_HIGH}]}
    assert severity_word_from_osv_body(body) == "high"


def test_cvss_v4_vector_maps():
    body = {"severity": [{"type": "CVSS_V4", "score": _V4_CRITICAL}]}
    assert severity_word_from_osv_body(body) == "critical"


def test_prefers_newest_cvss_version():
    body = {"severity": [
        {"type": "CVSS_V2", "score": _V2_HIGH},        # 7.5 → high
        {"type": "CVSS_V3", "score": _V3_CRITICAL},    # 9.8 → critical
    ]}
    assert severity_word_from_osv_body(body) == "critical"


def test_word_wins_over_cvss_vector():
    body = {
        "database_specific": {"severity": "LOW"},
        "severity": [{"type": "CVSS_V3", "score": _V3_CRITICAL}],
    }
    assert severity_word_from_osv_body(body) == "low"


def test_no_severity_returns_none():
    assert severity_word_from_osv_body({}) is None


def test_garbage_vector_does_not_crash():
    body = {"severity": [{"type": "CVSS_V3", "score": "not-a-vector"}]}
    assert severity_word_from_osv_body(body) is None
    assert base_score_from_vector("not-a-vector") is None


def test_finding_severity_falls_back_to_unknown():
    # sca_findings applies the "unknown" fallback for the Finding row.
    assert _severity_level({}) == "unknown"
    assert _severity_level({"severity": [{"type": "CVSS_V3", "score": _V3_CRITICAL}]}) == "critical"


def test_mirror_column_falls_back_to_none():
    # store keeps the nullable column as None when undeterminable.
    assert _derive_severity({}) is None
    assert _derive_severity({"severity": [{"type": "CVSS_V2", "score": _V2_HIGH}]}) == "high"
