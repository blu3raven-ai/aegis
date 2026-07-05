"""Tests for runner.verification.schemas — unified Evidence + Verdict."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from runner.verification.schemas import (
    Evidence,
    EvidenceKind,
    VerificationResultModel,
    Verdict,
    coerce_evidence_list,
)


# ---------------------------------------------------------------------------
# EvidenceKind enum
# ---------------------------------------------------------------------------


def test_evidence_kind_covers_every_scanner():
    """Closed set — adding a new scanner forces a corresponding update here."""
    members = {k.value for k in EvidenceKind}
    expected = {
        # SAST
        "source", "sink", "gate",
        # secrets
        "secret", "context",
        # SCA
        "advisory", "import_site", "manifest",
        # cross-scanner / agentic
        "tool_call_log", "runtime_log",
    }
    assert members == expected


# ---------------------------------------------------------------------------
# File-grounded evidence
# ---------------------------------------------------------------------------


def test_file_grounded_evidence_requires_file_and_line():
    Evidence(kind=EvidenceKind.IMPORT_SITE, file="a.js", line=3, snippet="require('lodash')")

    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.IMPORT_SITE, snippet="x")  # missing file/line

    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.IMPORT_SITE, file="a.js", snippet="x")  # missing line


def test_file_grounded_evidence_rejects_non_positive_line():
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.SOURCE, file="a.py", line=0, snippet="x")
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.SOURCE, file="a.py", line=-1, snippet="x")


def test_sast_kinds_all_accept_file_grounding():
    for kind in (EvidenceKind.SOURCE, EvidenceKind.SINK, EvidenceKind.GATE):
        Evidence(kind=kind, file="a.py", line=1, snippet="x")


def test_secret_kinds_accept_file_grounding():
    for kind in (EvidenceKind.SECRET, EvidenceKind.CONTEXT):
        Evidence(kind=kind, file="cfg.env", line=2, snippet="API_KEY=...")


# ---------------------------------------------------------------------------
# External-sourced evidence
# ---------------------------------------------------------------------------


def test_advisory_evidence_requires_source(tmp_path=None):
    Evidence(kind=EvidenceKind.ADVISORY, source="CVE-2021-23337", snippet="prototype pollution")

    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.ADVISORY, snippet="x")


def test_tool_call_log_requires_source():
    Evidence(
        kind=EvidenceKind.TOOL_CALL_LOG,
        source="investigator/abc123",
        snippet="grep_repo('foo') -> 0 matches",
    )
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.TOOL_CALL_LOG, snippet="x")


def test_runtime_log_requires_source():
    Evidence(
        kind=EvidenceKind.RUNTIME_LOG,
        source="prod-2026-06-14",
        snippet="request blocked by sanitizer",
    )
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.RUNTIME_LOG, snippet="x")


# ---------------------------------------------------------------------------
# Universal validators
# ---------------------------------------------------------------------------


def test_snippet_required_non_empty():
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.IMPORT_SITE, file="a.js", line=1, snippet="")


def test_extra_fields_rejected():
    with pytest.raises(ValidationError):
        Evidence(
            kind=EvidenceKind.IMPORT_SITE,
            file="a.js",
            line=1,
            snippet="x",
            invented="nope",
        )


# ---------------------------------------------------------------------------
# from_dict + coerce_evidence_list
# ---------------------------------------------------------------------------


def test_from_dict_drops_unknown_keys():
    e = Evidence.from_dict(
        {"kind": "import_site", "file": "a.js", "line": 1, "snippet": "x", "extra": "ignored"}
    )
    assert e.kind == EvidenceKind.IMPORT_SITE.value
    assert e.snippet == "x"


def test_coerce_evidence_list_drops_malformed_items():
    items = [
        {"kind": "import_site", "file": "a.js", "line": 1, "snippet": "ok"},
        {"kind": "advisory", "snippet": "missing source"},   # invalid
        {"kind": "import_site", "snippet": "missing file"},  # invalid
        {"kind": "advisory", "source": "CVE-x", "snippet": "good"},
    ]
    result = coerce_evidence_list(items)
    assert len(result) == 2
    assert result[0].kind == EvidenceKind.IMPORT_SITE.value
    assert result[1].kind == EvidenceKind.ADVISORY.value


# ---------------------------------------------------------------------------
# Verdict enum
# ---------------------------------------------------------------------------


def test_verdict_enum_values_match_finding_db_constraint():
    """The Finding DB column constraint allows exactly these four values."""
    assert {v.value for v in Verdict} == {
        "confirmed", "needs_verify", "possible", "ruled_out",
    }


# ---------------------------------------------------------------------------
# VerificationResultModel
# ---------------------------------------------------------------------------


def test_verification_result_model_minimal():
    r = VerificationResultModel(verdict=Verdict.POSSIBLE)
    assert r.verdict == Verdict.POSSIBLE.value
    assert r.evidence == []
    assert r.exploit_chain == ""
    assert r.tokens_in == 0


def test_verification_result_from_legacy_dataclass():
    from runner.verification.pipeline import VerificationResult

    legacy = VerificationResult(
        verdict="confirmed",
        exploit_chain="chain text",
        evidence=[
            {"kind": "advisory", "source": "CVE-X", "snippet": "vuln"},
            {"kind": "import_site", "file": "a.js", "line": 1, "snippet": "require('x')"},
        ],
        tokens_in=100,
        tokens_out=50,
        verification_metadata={"model": "stub"},
    )
    r = VerificationResultModel.from_legacy(legacy)
    assert r.verdict == "confirmed"
    assert len(r.evidence) == 2
    assert r.tokens_in == 100
    assert r.verification_metadata["model"] == "stub"


def test_verification_result_from_legacy_dict_form():
    raw = {
        "verdict": "ruled_out",
        "exploit_chain": "",
        "evidence": [{"kind": "advisory", "source": "CVE-X", "snippet": "ok"}],
        "tokens_in": 0,
        "tokens_out": 0,
        "verification_metadata": {},
    }
    r = VerificationResultModel.from_legacy(raw)
    assert r.verdict == "ruled_out"
    assert len(r.evidence) == 1


def test_verification_result_drops_malformed_evidence_silently():
    raw = {
        "verdict": "possible",
        "exploit_chain": "",
        "evidence": [
            {"kind": "advisory", "snippet": "no source"},  # invalid
            {"kind": "advisory", "source": "CVE-Y", "snippet": "good"},
        ],
        "tokens_in": 0,
        "tokens_out": 0,
        "verification_metadata": {},
    }
    r = VerificationResultModel.from_legacy(raw)
    assert len(r.evidence) == 1  # only the valid one survives
