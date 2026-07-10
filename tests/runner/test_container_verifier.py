"""Fixture tests for the container CVE enrichment verifier (LLM mocked)."""
from unittest.mock import MagicMock

from runner.verification.verifiers.container import verify_container_finding


def _llm_returning(content: str) -> MagicMock:
    llm = MagicMock()
    llm._model = "stub"
    llm.chat.return_value = MagicMock(content=content, tokens_in=1, tokens_out=1, prompt_hash="h")
    return llm


def test_enriches_container_finding_with_impact_and_fix():
    llm = _llm_returning(
        '{"exploit_chain":"attacker sends crafted input to the vulnerable parser",'
        '"title":"RCE via libfoo deserialization",'
        '"impact":"Remote code execution in the container",'
        '"reproduction":"send a crafted payload to the exposed endpoint",'
        '"attack_paths":[{"name":"network","steps":"reach the service then trigger parse"}],'
        '"mitigating_factors":["service not exposed by default"],'
        '"fix":"upgrade libfoo to 2.1.0","evidence":[]}'
    )
    finding = {"packageName": "libfoo", "packageVersion": "2.0.0", "cve": "CVE-9",
               "imageName": "acme/app", "imageTag": "1.2.3"}
    result = verify_container_finding(finding=finding, llm=llm)
    md = result.verification_metadata
    assert md["impact"] == "Remote code execution in the container"
    assert md["fix"] == "upgrade libfoo to 2.1.0"
    assert md["title"] == "RCE via libfoo deserialization"
    assert md["attack_paths"] and md["attack_paths"][0]["steps"]
    llm.chat.assert_called_once()


def test_schema_invalid_llm_content_falls_back_without_enrichment():
    llm = _llm_returning("not json")
    finding = {"packageName": "libfoo", "packageVersion": "2.0.0", "cve": "CVE-9"}
    result = verify_container_finding(finding=finding, llm=llm)
    assert "impact" not in result.verification_metadata
    assert result.verification_metadata.get("scanner") == "container_scanning"
