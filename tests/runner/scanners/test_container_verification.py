"""Integration tests for container verification wired into the container scanner."""
from __future__ import annotations

import json
import threading
from pathlib import Path

from runner.scanners._shared import JobEnv
from runner.scanners.container.scanner import ContainerScanner
from runner.verification.llm_client import LlmResponse


def _env(api_key: str | None = None) -> JobEnv:
    env_vars: dict[str, str] = {}
    if api_key:
        env_vars["LLM_API_KEY"] = api_key
    return JobEnv({"envVars": env_vars})


class _StubLlm:
    def __init__(self, responses):
        self._r = list(responses)
        self.calls = []
        self._model = "stub"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        return LlmResponse(
            content=self._r.pop(0),
            tokens_in=100,
            tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


def _make_findings_jsonl(out_dir: Path, findings: list[dict]) -> None:
    fp = out_dir / "findings.jsonl"
    fp.write_text("\n".join(json.dumps(f) for f in findings) + "\n")


def _basic_finding(**overrides) -> dict:
    base = {
        "advisoryId": "CVE-2023-12345",
        "advisoryAliases": ["GHSA-aaaa-bbbb-cccc"],
        "packageName": "openssl",
        "packageVersion": "1.1.1k-r0",
        "ecosystem": "apk",
        "severity": "high",
        "cvssScore": 7.5,
        "fixedVersion": "1.1.1l-r0",
        "fixState": "fixed",
        "manifestPath": "/lib/apk/db/installed",
        "manifestSnippet": "P:openssl\nV:1.1.1k-r0",
        "summary": "Buffer overflow",
        "description": "Heap overflow via crafted TLS handshake.",
        "imageName": "acme-org/web",
        "imageTag": "1.2.3",
        "imageDigest": "sha256:abcdef0123",
        "advisoryDetail": {
            "advisoryId": "CVE-2023-12345",
            "summary": "Buffer overflow",
            "description": "openssl prior to 1.1.1l vulnerable to heap overflow.",
            "references": [],
            "cwes": ["CWE-122"],
            "vulnerableVersionRange": "< 1.1.1l",
        },
    }
    base.update(overrides)
    return base


def _unlimited_budget():
    from runner.verification.budget import ScanBudget
    return ScanBudget(scan_budget=1_000_000, daily_remaining=1_000_000)


# ---------------------------------------------------------------------------
# LLM disabled path
# ---------------------------------------------------------------------------


def test_verify_marks_findings_llm_disabled_when_no_key(tmp_path, monkeypatch):
    """No BYO LLM key configured — every finding gets verdict=None + skip reason."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    _make_findings_jsonl(tmp_path, [_basic_finding()])

    scanner = ContainerScanner()
    scanner._verify_findings_file(tmp_path / "findings.jsonl", tmp_path, env=_env())

    line = (tmp_path / "findings.jsonl").read_text().strip()
    f = json.loads(line)
    assert f["verdict"] is None
    assert f["verification_metadata"]["skipped"] == "llm_disabled"


def test_verify_no_op_when_findings_file_missing(tmp_path):
    scanner = ContainerScanner()
    scanner._verify_findings_file(tmp_path / "missing.jsonl", tmp_path, env=_env())


# ---------------------------------------------------------------------------
# Severity gate and budget skips
# ---------------------------------------------------------------------------


def test_below_severity_skips_llm(tmp_path):
    finding = _basic_finding(severity="medium")

    scanner = ContainerScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "below_severity"
    assert llm.calls == []


def test_negligible_severity_skips_llm(tmp_path):
    finding = _basic_finding(severity="negligible")

    scanner = ContainerScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert verified[0]["verification_metadata"]["skipped"] == "below_severity"


def test_budget_exhausted_yields_possible(tmp_path):
    finding = _basic_finding()

    from runner.verification.budget import ScanBudget
    exhausted = ScanBudget(scan_budget=0, daily_remaining=10_000)

    scanner = ContainerScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=exhausted,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"]["skipped"] == "scan_budget"
    assert llm.calls == []


# ---------------------------------------------------------------------------
# Full verification path
# ---------------------------------------------------------------------------


def test_full_verify_invokes_llm_for_high_severity(tmp_path):
    finding = _basic_finding(severity="high")

    scanner = ContainerScanner()
    llm = _StubLlm([
        json.dumps({
            "exploit_chain": "openssl SSL_read reachable via HTTPS listener",
            "evidence": [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "heap overflow in SSL_read",
                },
            ],
        }),
        json.dumps({"mitigation_found": False, "reasoning": ""}),
    ])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "confirmed"
    assert verified[0]["exploit_chain"]
    assert len(llm.calls) == 2  # Hunter + Skeptic


def test_full_verify_invokes_llm_for_critical(tmp_path):
    finding = _basic_finding(severity="critical")

    scanner = ContainerScanner()
    llm = _StubLlm([
        json.dumps({"exploit_chain": "", "evidence": []}),
    ])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"]["reason"] == "hunter_no_chain"


def test_skeptic_mitigation_yields_ruled_out(tmp_path):
    finding = _basic_finding()

    scanner = ContainerScanner()
    llm = _StubLlm([
        json.dumps({
            "exploit_chain": "openssl installed",
            "evidence": [
                {
                    "kind": "advisory",
                    "source": "CVE-2023-12345",
                    "snippet": "heap overflow",
                },
            ],
        }),
        json.dumps({
            "mitigation_found": True,
            "mitigation_file": "/lib/apk/db/installed",
            "mitigation_line": 1,
            "mitigation_snippet": "P:openssl",
            "reasoning": "image is a build stage, openssl never invoked",
        }),
    ])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] == "ruled_out"
    assert verified[0]["verification_metadata"]["ruled_out_reason"]["file"] == (
        "/lib/apk/db/installed"
    )


# ---------------------------------------------------------------------------
# Exception isolation
# ---------------------------------------------------------------------------


def test_llm_error_recorded_does_not_raise(tmp_path):
    finding = _basic_finding()

    class _ExplodingLlm:
        _model = "boom"

        def chat(self, *a, **kw):
            raise RuntimeError("upstream timeout")

    scanner = ContainerScanner()
    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=_ExplodingLlm(),
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert "llm_error" in verified[0]["verification_metadata"]["skipped"]


def test_per_finding_exception_does_not_poison_others(tmp_path):
    """One bad finding shouldn't poison subsequent ones."""
    good = _basic_finding(advisoryId="CVE-good")
    bad = _basic_finding(advisoryId="CVE-bad")

    # First call raises, second returns hunter_no_chain
    class _PartiallyExplodingLlm:
        _model = "stub"

        def __init__(self):
            self.call_count = 0

        def chat(self, *a, **kw):
            self.call_count += 1
            if self.call_count == 1:
                raise RuntimeError("transient")
            return LlmResponse(
                content=json.dumps({"exploit_chain": "", "evidence": []}),
                tokens_in=10,
                tokens_out=5,
                prompt_hash=f"h-{self.call_count}",
            )

    scanner = ContainerScanner()
    verified = scanner._maybe_verify_container(
        findings=[bad, good],
        out_dir=tmp_path,
        llm=_PartiallyExplodingLlm(),
        scan_budget=_unlimited_budget(),
    )
    assert verified[0]["verdict"] is None
    assert "llm_error" in verified[0]["verification_metadata"]["skipped"]
    assert verified[1]["verdict"] == "possible"


# ---------------------------------------------------------------------------
# File round-trip
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Cooperative cancellation (C9)
# ---------------------------------------------------------------------------


def test_cancel_event_set_before_loop_marks_all_findings_cancelled(tmp_path):
    """When cancel is set up-front, every finding gets verdict=possible + cancelled."""
    findings = [_basic_finding(advisoryId=f"CVE-{i}") for i in range(3)]
    cancel = threading.Event()
    cancel.set()

    scanner = ContainerScanner()
    llm = _StubLlm([])

    verified = scanner._maybe_verify_container(
        findings=findings,
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=cancel,
    )

    assert len(verified) == 3
    for f in verified:
        assert f["verdict"] == "possible"
        assert f["verification_metadata"]["skipped"] == "cancelled"
    # No LLM round-trips should have happened.
    assert llm.calls == []


def test_cancel_event_set_midway_short_circuits_remaining(tmp_path):
    """A mid-loop cancel must mark the rest cancelled without further LLM calls."""

    class _CancellingLlm:
        _model = "stub"

        def __init__(self, cancel):
            self.calls = 0
            self._cancel = cancel

        def chat(self, *a, **kw):
            self.calls += 1
            # Trip the cancel after the first hunter response so subsequent
            # findings should be short-circuited.
            self._cancel.set()
            return LlmResponse(
                content=json.dumps({"exploit_chain": "", "evidence": []}),
                tokens_in=10,
                tokens_out=5,
                prompt_hash="h",
            )

    cancel = threading.Event()
    llm = _CancellingLlm(cancel)
    findings = [_basic_finding(advisoryId=f"CVE-{i}") for i in range(3)]

    scanner = ContainerScanner()
    verified = scanner._maybe_verify_container(
        findings=findings,
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=cancel,
    )

    # First finding ran to completion (one hunter call, no chain -> possible).
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"].get("reason") == "hunter_no_chain"
    # Remaining findings were short-circuited as cancelled.
    for f in verified[1:]:
        assert f["verdict"] == "possible"
        assert f["verification_metadata"]["skipped"] == "cancelled"
    assert llm.calls == 1


def test_cancel_event_none_runs_full_loop(tmp_path):
    """cancel_event=None is the default and must not change behaviour."""
    finding = _basic_finding()
    scanner = ContainerScanner()
    llm = _StubLlm([
        json.dumps({"exploit_chain": "", "evidence": []}),
    ])

    verified = scanner._maybe_verify_container(
        findings=[finding],
        out_dir=tmp_path,
        llm=llm,
        scan_budget=_unlimited_budget(),
        cancel_event=None,
    )
    assert verified[0]["verdict"] == "possible"
    assert verified[0]["verification_metadata"].get("reason") == "hunter_no_chain"


def test_verify_findings_file_round_trip_preserves_other_fields(tmp_path, monkeypatch):
    """Verifier rewrites findings.jsonl preserving all non-verdict fields."""
    monkeypatch.delenv("LLM_API_KEY", raising=False)

    finding = _basic_finding()
    _make_findings_jsonl(tmp_path, [finding])

    scanner = ContainerScanner()
    scanner._verify_findings_file(tmp_path / "findings.jsonl", tmp_path, env=_env())

    line = (tmp_path / "findings.jsonl").read_text().strip()
    out = json.loads(line)
    # Original fields preserved
    assert out["advisoryId"] == finding["advisoryId"]
    assert out["packageName"] == finding["packageName"]
    assert out["imageName"] == finding["imageName"]
    # Verdict + metadata added
    assert "verdict" in out
    assert "verification_metadata" in out
