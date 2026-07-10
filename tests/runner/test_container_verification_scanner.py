"""Tests for the container verification scanner (job handler)."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from runner.scanners.container_verification.scanner import ContainerVerificationScanner


def _job(**env) -> dict:
    return {"jobId": "cv-1", "type": "container_verification", "envVars": env}


def _targets(*targets: dict) -> str:
    return json.dumps(list(targets))


def _enriching_llm() -> MagicMock:
    llm = MagicMock()
    llm._model = "stub"
    llm.chat.return_value = MagicMock(
        content=(
            '{"exploit_chain":"attacker sends crafted input to the vulnerable parser",'
            '"title":"RCE via libfoo deserialization",'
            '"impact":"Remote code execution in the container",'
            '"reproduction":"send a crafted payload to the exposed endpoint",'
            '"attack_paths":[{"name":"network","steps":"reach the service then trigger parse"}],'
            '"mitigating_factors":["service not exposed by default"],'
            '"fix":"upgrade libfoo to 2.1.0","evidence":[]}'
        ),
        tokens_in=1,
        tokens_out=1,
        prompt_hash="h",
    )
    return llm


def test_dispatcher_registers_container_verification_type():
    from runner.core.dispatcher import get_scanner, supported_types

    assert "container_verification" in supported_types()
    assert isinstance(get_scanner("container_verification"), ContainerVerificationScanner)


def test_verified_target_written_per_finding_id(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "runner.scanners.container_verification.scanner.build_llm_client",
        lambda env: _enriching_llm(),
    )
    register_calls: list = []
    monkeypatch.setattr(
        "runner.scanners.container_verification.scanner.register_output",
        lambda out_dir, path, repo: register_calls.append((path.name, repo)),
    )

    job = _job(
        RUN_ID="run-42",
        ORG_LABEL="acme-org",
        LLM_API_KEY="test-key",
        CONTAINER_VERIFY_TARGETS=_targets(
            {
                "finding_id": "1",
                "packageName": "libfoo",
                "packageVersion": "2.0.0",
                "cve": "CVE-9",
            }
        ),
    )

    result = ContainerVerificationScanner().run_scan(job, tmp_path)
    assert result.exit_code == 0

    results_file = next(tmp_path.rglob("container-verify-results.json"))
    payload = json.loads(results_file.read_text())
    assert payload["run_id"] == "run-42"
    by_id = {r["finding_id"]: r for r in payload["results"]}
    assert by_id["1"]["verification_metadata"]["impact"] == "Remote code execution in the container"
    assert register_calls and register_calls[0][0] == "container-verify-results.json"
