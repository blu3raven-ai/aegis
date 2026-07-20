"""Tests for the deterministic secret rotation runbook.

One generic playbook backs every secret finding. These guard its safety
invariants: revoke is always the first, destructive step; history-scrub never
precedes revoke; the runbook is never empty; the detector name surfaces as the
credential label; and no provider-specific URLs are hardcoded (they'd be wrong
for self-hosted GitLab/Gitea). The runbook is attached to every emitted secret
finding without any LLM involvement.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from runner.scanners.secrets import normalize
from runner.scanners.secrets.remediation import build_secret_runbook


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


# Every detector uses the same generic steps; the detector name only surfaces as
# the credential label.
_DETECTORS = ["AWS", "GCP", "Github", "GitLab", "Gitea", "OpenAI", "Slack", "Stripe"]


@pytest.mark.parametrize("detector", _DETECTORS)
def test_runbook_surfaces_detector_as_label(detector: str) -> None:
    runbook = build_secret_runbook(_finding(detector))

    assert runbook["kind"] == "rotation"
    assert runbook["source"] == "deterministic"
    assert runbook["provider"] == detector
    assert detector in runbook["title"]
    assert detector in runbook["rationale"]


@pytest.mark.parametrize("detector", _DETECTORS)
def test_runbook_revoke_first_and_scrub_after(detector: str) -> None:
    runbook = build_secret_runbook(_finding(detector))
    steps = runbook["steps"]

    assert steps, "steps must never be empty"
    assert steps[0]["order"] == 1
    assert steps[0]["destructive"] is True
    assert _revoke_order(runbook) == 1
    assert _scrub_order(runbook) > _revoke_order(runbook)
    assert [s["order"] for s in steps] == list(range(1, len(steps) + 1))


def test_runbook_has_no_provider_specific_urls() -> None:
    # No hardcoded provider rotation/push-protection URLs — they'd be wrong for
    # self-hosted GitLab/Gitea and add no value for SaaS the operator knows.
    runbook = build_secret_runbook(_finding("GitLab"))
    blob = json.dumps(runbook)
    for verboten in ("github.com/settings", "gitlab.com/-/", "docs.github.com"):
        assert verboten not in blob, f"hardcoded provider URL leaked into runbook: {verboten}"


def test_unknown_detector_uses_generic_steps() -> None:
    runbook = build_secret_runbook(_finding("SomeRandomHighEntropyToken"))

    assert runbook["kind"] == "rotation"
    assert runbook["source"] == "deterministic"
    assert runbook["steps"], "generic runbook must not be empty"
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
    assert out[0]["recommended_fix"]["verifiedActive"] is True
    assert out[0]["recommended_fix"]["provider"] == "AWS"
    assert out[1]["recommended_fix"]["verifiedActive"] is False
    assert out[2]["recommended_fix"]["provider"] == "MysteryDetector"
