"""Fixture tests for the dependency reachability verifier (LLM mocked)."""
from unittest.mock import MagicMock

from runner.verification.verifiers.deps import verify_deps_finding


def _llm_returning(content: str) -> MagicMock:
    llm = MagicMock()
    llm._model = "stub"
    llm.chat.return_value = MagicMock(
        content=content, tokens_in=1, tokens_out=1, prompt_hash="h"
    )
    return llm


def test_package_not_imported_is_no_path_without_llm(tmp_path):
    (tmp_path / "main.py").write_text("import os\n")
    llm = _llm_returning("{}")
    finding = {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}

    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    assert result.verification_metadata.get("reachability") == "no_path"
    llm.chat.assert_not_called()  # cheap pre-filter must not spend on the LLM


def test_imported_reachable_via_llm(tmp_path):
    (tmp_path / "main.py").write_text("import evilpkg\nevilpkg.vuln_fn()\n")
    llm = _llm_returning(
        '{"reachability":"reachable","evidence":'
        '[{"kind":"sink","file":"main.py","line":2,"snippet":"evilpkg.vuln_fn()"}]}'
    )
    finding = {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}

    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    assert result.verification_metadata.get("reachability") == "reachable"
    llm.chat.assert_called_once()


def test_ungrounded_no_path_becomes_unknown(tmp_path):
    (tmp_path / "main.py").write_text("import evilpkg\n")
    llm = _llm_returning(
        '{"reachability":"no_path","evidence":'
        '[{"kind":"context","file":"ghost.py","line":9,"snippet":"unrelated_api()"}]}'
    )
    finding = {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}

    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    # Cited file does not exist → the no_path claim is ungrounded → downgrade.
    assert result.verification_metadata.get("reachability") == "unknown"


def test_no_path_with_empty_llm_evidence_stays_visible(tmp_path):
    # The package IS imported (so the deterministic import sites are real), but
    # the model returns no_path citing NOTHING. Those import sites must not be
    # borrowed as grounding — an uncited no_path must downgrade to unknown so a
    # genuinely reachable vuln is never hidden.
    (tmp_path / "main.py").write_text("import evilpkg\nevilpkg.vuln_fn()\n")
    llm = _llm_returning('{"reachability":"no_path","evidence":[]}')
    finding = {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}

    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    assert result.verification_metadata.get("reachability") == "unknown"


def test_schema_invalid_llm_content_falls_back_to_unknown(tmp_path):
    (tmp_path / "main.py").write_text("import evilpkg\n")
    # 'maybe' is outside the strict tri-state → schema validation fails.
    llm = _llm_returning('{"reachability":"maybe","evidence":[]}')
    finding = {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}

    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    assert result.verification_metadata.get("reachability") == "unknown"


# ---------------------------------------------------------------------------
# Frontier escalation tier (dormant unless an escalation client is passed).
# The deps verifier uses a single-shot ``chat`` + manual ``model_validate_json``
# rather than ``chat_json``, so the escalation trigger is the schema-invalid
# branch: a frontier tier that succeeds can only surface a real signal, and the
# citation-grounding rule still gates any ``no_path`` it emits.
# ---------------------------------------------------------------------------

from runner.verification.llm_client import LlmClient, LlmResponse


class _ChatStubLlm(LlmClient):
    """Scripts ``chat`` so two tiers can be exercised independently."""

    def __init__(self, contents):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub-model")
        self._contents = list(contents)
        self.calls = 0

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls += 1
        content = self._contents.pop(0)
        return LlmResponse(content=content, tokens_in=100, tokens_out=50,
                           prompt_hash=f"h-{self.calls}")


def _importing_finding():
    # ``evilpkg`` is imported by the seeded repo, so the deterministic pre-filter
    # does NOT short-circuit and the LLM call (and escalation) actually runs.
    return {"packageName": "evilpkg", "packageVersion": "1.0.0", "cve": "CVE-1", "detail": {}}


def _seed_repo(tmp_path):
    (tmp_path / "main.py").write_text("import evilpkg\nevilpkg.vuln_fn()\n")
    return _importing_finding()


def test_tier_default_stamped_and_no_escalation_by_default(tmp_path):
    finding = _seed_repo(tmp_path)
    llm = _ChatStubLlm([
        '{"reachability":"reachable","evidence":'
        '[{"kind":"sink","file":"main.py","line":2,"snippet":"evilpkg.vuln_fn()"}]}',
    ])
    result = verify_deps_finding(finding=finding, repo_root=str(tmp_path), llm=llm)
    assert result.verification_metadata["tier"] == "default"
    assert "escalated" not in result.verification_metadata
    assert result.verification_metadata["reachability"] == "reachable"


def test_escalates_to_frontier_when_default_schema_fails(tmp_path):
    """Default emits schema-invalid content -> the frontier tier retries once."""
    finding = _seed_repo(tmp_path)
    default = _ChatStubLlm(['{"reachability":"maybe","evidence":[]}'])  # invalid tri-state
    frontier = _ChatStubLlm([
        '{"reachability":"reachable","evidence":'
        '[{"kind":"sink","file":"main.py","line":2,"snippet":"evilpkg.vuln_fn()"}]}',
    ])

    result = verify_deps_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verification_metadata["reachability"] == "reachable"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["tier"] == "frontier"
    assert default.calls == 1   # default tier tried once, failed schema
    assert frontier.calls == 1  # frontier tier retried and succeeded
    # Tokens accumulate across BOTH tiers.
    assert result.tokens_in == 200


def test_no_escalation_when_default_succeeds(tmp_path):
    finding = _seed_repo(tmp_path)
    default = _ChatStubLlm([
        '{"reachability":"reachable","evidence":'
        '[{"kind":"sink","file":"main.py","line":2,"snippet":"evilpkg.vuln_fn()"}]}',
    ])
    frontier = _ChatStubLlm(["{}"])  # should never be touched

    result = verify_deps_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verification_metadata["reachability"] == "reachable"
    assert result.verification_metadata["tier"] == "default"
    assert frontier.calls == 0


def test_escalation_that_also_fails_stays_unknown(tmp_path):
    finding = _seed_repo(tmp_path)
    default = _ChatStubLlm(['{"reachability":"maybe","evidence":[]}'])
    frontier = _ChatStubLlm(['{"reachability":"also-bad","evidence":[]}'])

    result = verify_deps_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verification_metadata["reachability"] == "unknown"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["reason"].startswith("schema_invalid:")


def test_frontier_no_path_still_grounded_by_citation_rule(tmp_path):
    """Escalation surfaces a signal, but the grounding rule still gates no_path.

    The frontier tier emits ``no_path`` citing a file that doesn't exist. Even
    after escalation, the recall-safety rule downgrades it to ``unknown`` —
    escalation can only surface a *grounded* signal, never hide a real one.
    """
    finding = _seed_repo(tmp_path)
    default = _ChatStubLlm(['{"reachability":"maybe","evidence":[]}'])
    frontier = _ChatStubLlm([
        '{"reachability":"no_path","evidence":'
        '[{"kind":"context","file":"ghost.py","line":9,"snippet":"unrelated_api()"}]}',
    ])

    result = verify_deps_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    # Escalated, but the ungrounded no_path still downgrades to unknown.
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["reachability"] == "unknown"

