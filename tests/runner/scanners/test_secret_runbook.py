"""Tests for the deterministic secret rotation runbook.

These guard the safety invariants of the operational remediation: revoke is
always the first, destructive step; history-scrub never precedes revoke; the
runbook is never empty (generic fallback); and it is attached to every emitted
secret finding without any LLM involvement.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from runner.scanners.secrets import normalize
from runner.scanners.secrets.remediation import (
    _normalize_detector,
    build_secret_runbook,
)


_SCRUB_LABEL = "Purge the secret from git history"


def _finding(detector: str, *, verified: bool | None = None) -> dict:
    f: dict = {"DetectorName": detector}
    if verified is not None:
        f["Verified"] = verified
    return f


def _revoke_order(runbook: dict) -> int:
    return next(s["order"] for s in runbook["steps"] if s.get("destructive"))


def _scrub_order(runbook: dict) -> int:
    return next(s["order"] for s in runbook["steps"] if s["label"] == _SCRUB_LABEL)


# ---------------------------------------------------------------------------
# Known detectors map to their provider playbook
# ---------------------------------------------------------------------------

_KNOWN = [
    ("AWS", "AWS"),
    ("GCP", "Google Cloud (service account key)"),
    ("Github", "GitHub"),
    ("OpenAI", "OpenAI"),
    ("Slack", "Slack"),
    ("Stripe", "Stripe"),
]


@pytest.mark.parametrize("detector,provider", _KNOWN)
def test_known_detector_maps_to_provider_playbook(detector: str, provider: str) -> None:
    runbook = build_secret_runbook(_finding(detector))

    assert runbook["kind"] == "rotation"
    assert runbook["source"] == "deterministic"
    assert runbook["provider"] == provider
    assert provider in runbook["title"]
    assert detector in runbook["rationale"]


@pytest.mark.parametrize("detector,_provider", _KNOWN)
def test_known_detector_revoke_first_and_scrub_after(detector: str, _provider: str) -> None:
    runbook = build_secret_runbook(_finding(detector))
    steps = runbook["steps"]

    assert steps, "steps must never be empty"
    # Revoke is order 1 and destructive.
    assert steps[0]["order"] == 1
    assert steps[0]["destructive"] is True
    assert _revoke_order(runbook) == 1
    # History scrub comes strictly after revoke.
    assert _scrub_order(runbook) > _revoke_order(runbook)
    # Orders are a contiguous 1..N sequence.
    assert [s["order"] for s in steps] == list(range(1, len(steps) + 1))


# ---------------------------------------------------------------------------
# Unknown detector -> generic playbook
# ---------------------------------------------------------------------------

def test_unknown_detector_falls_back_to_generic() -> None:
    runbook = build_secret_runbook(_finding("SomeRandomHighEntropyToken"))

    assert _normalize_detector("SomeRandomHighEntropyToken") == "generic"
    assert runbook["kind"] == "rotation"
    assert runbook["source"] == "deterministic"
    assert runbook["steps"], "generic fallback must not be empty"
    # Revoke-first invariant holds for the generic playbook too.
    assert runbook["steps"][0]["order"] == 1
    assert runbook["steps"][0]["destructive"] is True
    assert _scrub_order(runbook) > _revoke_order(runbook)
    # Unknown detector name is surfaced as the provider label.
    assert runbook["provider"] == "SomeRandomHighEntropyToken"


def test_empty_detector_still_produces_runbook() -> None:
    runbook = build_secret_runbook({})

    assert runbook["provider"] is None
    assert runbook["title"] == "Rotate the exposed credential"
    assert runbook["steps"][0]["destructive"] is True
    assert _scrub_order(runbook) > _revoke_order(runbook)


# ---------------------------------------------------------------------------
# Detector-name normalization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "detector,expected_key",
    [
        ("AWS", "aws"),
        ("aws", "aws"),
        ("AWSSessionKey", "aws"),
        ("GCP", "gcp"),
        ("GitHubApp", "github"),
        ("github", "github"),
        ("SlackWebhook", "slack"),
        ("OpenAI", "openai"),
        ("Stripe", "stripe"),
        ("UnknownThing", "generic"),
    ],
)
def test_detector_normalization(detector: str, expected_key: str) -> None:
    assert _normalize_detector(detector) == expected_key


def test_trufflehog_variant_resolves_to_aws() -> None:
    """A TruffleHog DetectorName variant still lands on the AWS playbook."""
    runbook = build_secret_runbook(_finding("AWSSessionKey"))
    assert runbook["provider"] == "AWS"


# ---------------------------------------------------------------------------
# verifiedActive reflects the finding's verified flag
# ---------------------------------------------------------------------------

def test_verified_active_true_from_trufflehog_capital_key() -> None:
    assert build_secret_runbook(_finding("AWS", verified=True))["verifiedActive"] is True


def test_verified_active_false_when_unverified() -> None:
    assert build_secret_runbook(_finding("AWS", verified=False))["verifiedActive"] is False


def test_verified_active_reads_lowercase_canonical_key() -> None:
    assert build_secret_runbook({"detector": "AWS", "verified": True})["verifiedActive"] is True


def test_verified_active_defaults_false_when_absent() -> None:
    assert build_secret_runbook(_finding("AWS"))["verifiedActive"] is False


# ---------------------------------------------------------------------------
# Attachment in the always-on (non-LLM) emit path
# ---------------------------------------------------------------------------

def test_normalize_file_attaches_runbook_to_every_finding() -> None:
    """normalize_file runs before/independent of verification — every emitted
    finding must already carry a kind=rotation recommended_fix."""
    records = [
        {"DetectorName": "AWS", "Verified": True, "Raw": "AKIA..."},
        {"DetectorName": "Stripe", "Verified": False, "Raw": "sk_live_..."},
        {"DetectorName": "MysteryDetector", "Raw": "xxxx"},
    ]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "trufflehog.json"
        path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

        out = normalize.normalize_file(path, "trufflehog", "acme-org/widget")

    assert len(out) == len(records)
    for finding in out:
        fix = finding["recommended_fix"]
        assert fix["kind"] == "rotation"
        assert fix["source"] == "deterministic"
        assert fix["steps"][0]["destructive"] is True
        # Provider-verified flag carried through from the trufflehog record.
    assert out[0]["recommended_fix"]["verifiedActive"] is True
    assert out[0]["recommended_fix"]["provider"] == "AWS"
    assert out[1]["recommended_fix"]["verifiedActive"] is False
    assert out[2]["recommended_fix"]["provider"] == "MysteryDetector"
