"""Integration tests for IaC verification wired into the IaC scanner."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from runner.scanners.iac.scanner import IacScanner
from runner.verification.llm_client import LlmClient, LlmResponse


class _StubLlm(LlmClient):
    def __init__(self, responses):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
        self._r = list(responses)
        self.calls = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        return LlmResponse(
            content=self._r.pop(0),
            tokens_in=100,
            tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


def _seed_repo(repo_root: Path) -> dict:
    """Lay down a minimal Terraform module and return a checkov-shaped finding."""
    (repo_root / "infra").mkdir(parents=True, exist_ok=True)
    (repo_root / "infra" / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "acme-org-data"\n'
        '}\n'
    )
    return {
        "tool": "iac_scanning",
        "check_id": "CKV_AWS_19",
        "title": "Ensure S3 bucket is encrypted at rest",
        "severity": "high",
        "file": "infra/s3.tf",
        "line": 1,
        "resource": "aws_s3_bucket.data",
        "guideline": "https://docs.bridgecrew.io/docs/s3_16-enable-encryption",
        "fingerprint": "abc1234567890def",
    }


def _unlimited_budget():
    from runner.verification.budget import ScanBudget
    return ScanBudget(scan_budget=1_000_000, daily_remaining=1_000_000)


# When any finding is pending verification, the scanner runs one advisory
# ground-truth recon pass over the findings' files before per-finding hunter /
# skeptic. Scripted-LLM tests must supply this leading response.
_GROUND_TRUTH = json.dumps({"baseline_refs": [], "accepted_behaviors": []})


# ---------------------------------------------------------------------------
# LLM-disabled path
# ---------------------------------------------------------------------------


def test_verify_marks_findings_llm_disabled(tmp_path):
    finding = _seed_repo(tmp_path)

    scanner = IacScanner()
    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=None,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "llm_disabled"


# ---------------------------------------------------------------------------
# Severity gate and budget skips
# ---------------------------------------------------------------------------


def test_below_severity_skips_llm(tmp_path):
    finding = _seed_repo(tmp_path)
    finding["severity"] = "medium"

    scanner = IacScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "below_severity"
    assert llm.calls == []


def test_low_severity_skips_llm(tmp_path):
    finding = _seed_repo(tmp_path)
    finding["severity"] = "low"

    scanner = IacScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "below_severity"


def test_budget_exhausted_yields_possible(tmp_path):
    finding = _seed_repo(tmp_path)

    from runner.verification.budget import ScanBudget
    exhausted = ScanBudget(scan_budget=0, daily_remaining=10_000)

    scanner = IacScanner()
    # Only the advisory ground-truth recon call fires; the per-finding budget
    # check then short-circuits before any hunter / skeptic round-trip.
    llm = _StubLlm([_GROUND_TRUTH])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=exhausted,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"]["skipped"] == "scan_budget"
    assert len(llm.calls) == 1


# ---------------------------------------------------------------------------
# Full verification path
# ---------------------------------------------------------------------------


def test_full_verify_invokes_llm_for_high_severity(tmp_path):
    finding = _seed_repo(tmp_path)

    scanner = IacScanner()
    llm = _StubLlm([
        _GROUND_TRUTH,
        json.dumps({
            "exploit_chain": "bucket holds PII without encryption",
            "evidence": [
                {
                    "kind": "resource",
                    "file": "infra/s3.tf",
                    "line": 1,
                    "snippet": 'resource "aws_s3_bucket" "data"',
                },
            ],
        }),
        json.dumps({"mitigation_found": False, "reasoning": ""}),
    ])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "confirmed"
    assert verified[0]["exploit_chain"]
    assert len(llm.calls) == 3  # Ground truth + Hunter + Skeptic


def test_full_verify_invokes_llm_for_critical(tmp_path):
    finding = _seed_repo(tmp_path)
    finding["severity"] = "critical"

    scanner = IacScanner()
    llm = _StubLlm([
        _GROUND_TRUTH,
        json.dumps({"exploit_chain": "", "evidence": []}),
    ])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"]["reason"] == "hunter_no_chain"


def test_skeptic_mitigation_yields_ruled_out(tmp_path):
    finding = _seed_repo(tmp_path)
    # Add a sibling policy file to make the mitigation plausible
    (tmp_path / "infra" / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "data" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  policy = "{}"\n'
        '}\n'
    )

    scanner = IacScanner()
    llm = _StubLlm([
        _GROUND_TRUTH,
        json.dumps({
            "exploit_chain": "bucket unencrypted",
            "evidence": [
                {
                    "kind": "resource",
                    "file": "infra/s3.tf",
                    "line": 1,
                    "snippet": 'resource "aws_s3_bucket"',
                },
            ],
        }),
        json.dumps({
            "mitigation_found": True,
            "mitigation_file": "infra/policy.tf",
            "mitigation_line": 1,
            "mitigation_snippet": "aws_s3_bucket_policy",
            "reasoning": "bucket policy restricts access to known principals",
        }),
    ])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "ruled_out"
    assert verified[0]["verification_metadata"]["ruled_out_reason"]["file"] == (
        "infra/policy.tf"
    )


# ---------------------------------------------------------------------------
# Exception isolation
# ---------------------------------------------------------------------------


def test_llm_error_recorded_does_not_raise(tmp_path):
    finding = _seed_repo(tmp_path)

    class _ExplodingLlm(LlmClient):
        def __init__(self):
            super().__init__(api_key="k", api_base_url="https://x/v1", model="boom")

        def chat(self, *a, **kw):
            raise RuntimeError("upstream timeout")

    scanner = IacScanner()
    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=_ExplodingLlm(),
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert "llm_error" in verified[0]["verification_metadata"]["skipped"]


def test_per_finding_exception_does_not_poison_others(tmp_path):
    bad = _seed_repo(tmp_path)
    bad["check_id"] = "CKV_AWS_BAD"
    good = dict(bad)
    good["check_id"] = "CKV_AWS_GOOD"

    class _PartiallyExplodingLlm(LlmClient):
        def __init__(self):
            super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
            self.call_count = 0

        def chat(self, *a, **kw):
            self.call_count += 1
            # Call 1 is the scan-level ground-truth recon (must succeed so the
            # per-finding path runs); call 2 is the first finding's hunter and
            # raises transiently.
            if self.call_count == 1:
                return LlmResponse(
                    content=json.dumps({"baseline_refs": [], "accepted_behaviors": []}),
                    tokens_in=10, tokens_out=5, prompt_hash="gt",
                )
            if self.call_count == 2:
                raise RuntimeError("transient")
            return LlmResponse(
                content=json.dumps({"exploit_chain": "", "evidence": []}),
                tokens_in=10,
                tokens_out=5,
                prompt_hash=f"h-{self.call_count}",
            )

    scanner = IacScanner()
    # max_workers=1 so the raising chat() call deterministically hits the first
    # finding; verification is concurrent now, so which finding sees the
    # transient error is otherwise nondeterministic. The isolation property under
    # test (one finding's exception doesn't poison others) holds either way.
    verified = scanner._maybe_verify_iac(
        findings=[bad, good],
        repo_root=str(tmp_path),
        llm=_PartiallyExplodingLlm(),
        scan_budget=_unlimited_budget(),
        max_workers=1,
    )
    assert verified[0]["verdict"] is None
    assert "llm_error" in verified[0]["verification_metadata"]["skipped"]
    assert verified[1]["verdict"] == "possible"


# ---------------------------------------------------------------------------
# Field preservation
# ---------------------------------------------------------------------------


def test_round_trip_preserves_other_fields(tmp_path):
    finding = _seed_repo(tmp_path)

    scanner = IacScanner()
    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=None,
        scan_budget=_unlimited_budget(),
    )
    out = verified[0]
    assert out["check_id"] == finding["check_id"]
    assert out["resource"] == finding["resource"]
    assert out["file"] == finding["file"]
    assert "verdict" in out
    assert "verification_metadata" in out


# ---------------------------------------------------------------------------
# Cooperative cancellation (C9)
# ---------------------------------------------------------------------------


def test_cancel_event_set_before_loop_marks_all_findings_cancelled(tmp_path):
    findings = [_seed_repo(tmp_path) for _ in range(3)]
    cancel = threading.Event()
    cancel.set()

    scanner = IacScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_iac(
        findings=findings,
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=cancel,
    )
    assert len(verified) == 3
    for f in verified:
        assert f["verdict"] == "possible"
        assert f["verification_metadata"]["skipped"] == "cancelled"
    assert llm.calls == []


def test_cancel_event_set_midway_short_circuits_remaining(tmp_path):
    class _CancellingLlm(LlmClient):
        def __init__(self, cancel):
            super().__init__(api_key="k", api_base_url="https://x/v1", model="stub")
            self.calls = 0
            self._cancel = cancel

        def chat(self, *a, **kw):
            self.calls += 1
            # Call 1 is the scan-level ground-truth recon; let it pass. Cancel
            # from the first finding's hunter (call 2) onward so the remaining
            # findings short-circuit before starting.
            if self.calls == 1:
                return LlmResponse(
                    content=json.dumps({"baseline_refs": [], "accepted_behaviors": []}),
                    tokens_in=10, tokens_out=5, prompt_hash="gt",
                )
            self._cancel.set()
            return LlmResponse(
                content=json.dumps({"exploit_chain": "", "evidence": []}),
                tokens_in=10,
                tokens_out=5,
                prompt_hash="h",
            )

    cancel = threading.Event()
    llm = _CancellingLlm(cancel)
    findings = [_seed_repo(tmp_path) for _ in range(3)]

    scanner = IacScanner()
    # max_workers=1 so the cancel short-circuit is deterministic: verification
    # now runs concurrently, and a cancel can't stop already-in-flight workers —
    # only ones that haven't started. Serialising isolates the per-worker cancel
    # check this test targets.
    verified = scanner._maybe_verify_iac(
        findings=findings,
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=cancel,
        max_workers=1,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"].get("reason") == "hunter_no_chain"
    for f in verified[1:]:
        assert f["verdict"] == "possible"
        assert f["verification_metadata"]["skipped"] == "cancelled"
    assert llm.calls == 2  # Ground truth + first finding's hunter


def test_cancel_event_none_runs_full_loop(tmp_path):
    finding = _seed_repo(tmp_path)
    scanner = IacScanner()
    llm = _StubLlm([
        _GROUND_TRUTH,
        json.dumps({"exploit_chain": "", "evidence": []}),
    ])

    verified = scanner._maybe_verify_iac(
        findings=[finding],
        repo_root=str(tmp_path),
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=None,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"].get("reason") == "hunter_no_chain"
