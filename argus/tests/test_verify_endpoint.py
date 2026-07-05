"""Round-trip tests for the Argus /v1/verify endpoint (LLM mocked)."""
from __future__ import annotations

import argus.service as service
from argus.verification.llm_client import LlmResponse
from fastapi.testclient import TestClient

client = TestClient(service.app)


class _FakeLlm:
    """Returns canned hunter/skeptic responses, mirroring runner test stubs."""

    def __init__(self, responses: list[str]) -> None:
        self._responses = list(responses)
        self._model = "fake-model"

    def chat(self, messages, *, temperature=0.0, max_tokens=1024) -> LlmResponse:
        content = self._responses.pop(0)
        return LlmResponse(content=content, tokens_in=100, tokens_out=50, prompt_hash="fake")


def _patch_llm(monkeypatch, responses: list[str]) -> None:
    monkeypatch.setattr(service, "build_llm", lambda: _FakeLlm(responses))


def test_health() -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_verify_requires_bearer() -> None:
    resp = client.post(
        "/v1/verify",
        json={"scan_id": "s1", "scanner": "code_scanning", "findings": []},
    )
    assert resp.status_code in (401, 403)


def test_verify_sast_confirms(monkeypatch) -> None:
    # Hunter cites a.py:1 "x = get_input()"; the materialized slice contains it,
    # so the real citation critic grounds the evidence -> confirmed.
    _patch_llm(
        monkeypatch,
        [
            '{"exploit_chain":"input x reaches sink",'
            '"evidence":[{"file":"a.py","line":1,"snippet":"x = get_input()","kind":"source"}]}',
            '{"mitigation_found":false,"reasoning":"no guard"}',
        ],
    )
    body = {
        "scan_id": "scan-1",
        "scanner": "code_scanning",
        "findings": [
            {
                "finding_id": "f1",
                "detail": {
                    "file": "a.py",
                    "line": 1,
                    "tool": "sast",
                    "rule": "x",
                    "severity": "high",
                },
                "code_context": {
                    "files": [
                        {"path": "a.py", "content": "x = get_input()\nsink(x)\n"}
                    ]
                },
            }
        ],
    }
    resp = client.post(
        "/v1/verify", json=body, headers={"Authorization": "Bearer test-token"}
    )
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert len(results) == 1
    assert results[0]["finding_id"] == "f1"
    assert results[0]["verdict"] == "confirmed"
    assert results[0]["source"] == "argus"


def test_verify_rejects_path_traversal(monkeypatch) -> None:
    _patch_llm(monkeypatch, ['{"exploit_chain":"","evidence":[]}'])
    body = {
        "scan_id": "scan-1",
        "scanner": "code_scanning",
        "findings": [
            {
                "finding_id": "f-bad",
                "detail": {"file": "a.py", "line": 1},
                "code_context": {
                    "files": [{"path": "../escape.py", "content": "pwned"}]
                },
            }
        ],
    }
    resp = client.post(
        "/v1/verify", json=body, headers={"Authorization": "Bearer test-token"}
    )
    # Fail-open: the traversal is rejected per-finding, not a 500.
    assert resp.status_code == 200
    result = resp.json()["results"][0]
    assert result["verdict"] == "needs_verify"
    assert "error" in result["verification_metadata"]
