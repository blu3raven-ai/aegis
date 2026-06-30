"""Round-trip tests for the Argus /v1/correlate endpoint (LLM/correlator mocked)."""
from __future__ import annotations

import argus.service as service
from argus.verification.schemas.correlation import (
    ChainSeverity,
    CorrelatedFinding,
    CorrelationVerdict,
)
from argus.verification.schemas.evidence import Evidence, EvidenceKind
from fastapi.testclient import TestClient

client = TestClient(service.app)


def _finding(fid: str, repository: str, *, scanner: str, file: str) -> dict:
    return {
        "detail": {
            "id": fid,
            "repository": repository,
            "scanner": scanner,
            "file": file,
            "line": 1,
        },
        "code_context": {"files": [{"path": file, "content": f"# {fid}\n"}]},
    }


def test_correlate_requires_bearer() -> None:
    resp = client.post("/v1/correlate", json={"budget": 50000, "findings": []})
    assert resp.status_code in (401, 403)


def test_correlate_empty_short_circuits(monkeypatch) -> None:
    # Empty batch must not even construct the LLM client.
    def _boom() -> None:
        raise AssertionError("build_llm must not be called for an empty batch")

    monkeypatch.setattr(service, "build_llm", _boom)
    resp = client.post(
        "/v1/correlate",
        json={"budget": 50000, "findings": []},
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"correlated_findings": []}


def test_correlate_round_trips(monkeypatch) -> None:
    captured: dict = {}

    chain = CorrelatedFinding(
        correlation_id="corr-abc123def456",
        verdict=CorrelationVerdict.CHAIN_CONFIRMED,
        chain_severity=ChainSeverity.HIGH,
        chain_description="secret leaks into an injectable sink",
        source_finding_ids=["f1", "f2"],
        evidence=[
            Evidence(
                kind=EvidenceKind.SOURCE,
                snippet="x = get_input()",
                file="app/db.py",
                line=1,
            )
        ],
    )

    def _fake_correlate(findings, *, repo_root_for, llm, budget):
        # The temp roots are torn down after the request returns, so snapshot
        # the materialized state here, while the correlator would see it.
        captured["findings"] = findings
        captured["budget"] = budget
        root = repo_root_for["acme-org/app"]
        captured["root_exists"] = root.exists()
        captured["slice_exists"] = (root / "app/db.py").exists()
        return [chain]

    monkeypatch.setattr(service, "correlate_findings", _fake_correlate)
    monkeypatch.setattr(service, "build_llm", lambda: object())

    body = {
        "budget": 12345,
        "findings": [
            _finding("f1", "acme-org/app", scanner="sast", file="app/db.py"),
            _finding("f2", "acme-org/app", scanner="secrets", file="app/db.py"),
        ],
    }
    resp = client.post(
        "/v1/correlate", json=body, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    out = resp.json()["correlated_findings"]
    assert len(out) == 1
    assert out[0]["correlation_id"] == "corr-abc123def456"
    assert out[0]["verdict"] == "chain_confirmed"
    assert out[0]["chain_description"] == "secret leaks into an injectable sink"
    assert out[0]["source_finding_ids"] == ["f1", "f2"]

    # The correlator was handed a per-repo root that existed and held the slice.
    assert captured["root_exists"]
    assert captured["slice_exists"]
    assert captured["budget"]._scan_budget == 12345


def test_correlate_malformed_body_422() -> None:
    resp = client.post(
        "/v1/correlate",
        json={"budget": 50000},
        headers={"Authorization": "Bearer test-token"},
    )
    assert resp.status_code == 422
