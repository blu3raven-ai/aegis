"""Tests for runner.verification.verifiers.iac.verify_iac_finding."""
from __future__ import annotations

import json
from pathlib import Path

from runner.verification.llm_client import LlmClient, LlmResponse
from runner.verification.verifiers.iac import verify_iac_finding


class _StubLlm(LlmClient):
    """Scripts ``chat`` so the inherited ``chat_json`` repair loop is exercised."""

    def __init__(self, responses):
        super().__init__(api_key="k", api_base_url="https://x/v1", model="stub-model")
        self._r = list(responses)
        self.calls = []

    def chat(self, messages, *, temperature=0.0, max_tokens=1024):
        self.calls.append(messages)
        content = self._r.pop(0)
        return LlmResponse(
            content=content,
            tokens_in=100,
            tokens_out=50,
            prompt_hash=f"h-{len(self.calls)}",
        )


def _seed_module(repo_root: Path) -> dict:
    """Lay down an S3 + bucket-policy fixture and return a checkov-shaped finding."""
    module = repo_root / "infra"
    module.mkdir(parents=True, exist_ok=True)

    bucket_tf = module / "s3.tf"
    bucket_tf.write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "acme-org-data"\n'
        '}\n'
    )
    policy_tf = module / "policy.tf"
    policy_tf.write_text(
        'resource "aws_s3_bucket_policy" "data" {\n'
        '  bucket = aws_s3_bucket.data.id\n'
        '  policy = jsonencode({ Statement = [{ Effect = "Deny", Action = "s3:*" }] })\n'
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


def _hunter_chain_json(chain: str, evidence: list[dict]) -> str:
    return json.dumps({"exploit_chain": chain, "evidence": evidence})


def _skeptic_json(mitigation: bool, **kw) -> str:
    return json.dumps({
        "mitigation_found": mitigation,
        "mitigation_file": kw.get("file"),
        "mitigation_line": kw.get("line"),
        "mitigation_snippet": kw.get("snippet"),
        "reasoning": kw.get("reasoning", ""),
    })


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def test_hunter_no_chain_yields_possible(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([_hunter_chain_json("", [])])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "possible"
    assert result.verification_metadata["reason"] == "hunter_no_chain"
    assert len(llm.calls) == 1  # skeptic skipped


def test_hunter_confirms_then_skeptic_disagrees_yields_confirmed(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([
        _hunter_chain_json(
            "bucket holds sensitive data and lacks server-side encryption",
            [
                {
                    "kind": "resource",
                    "file": "infra/s3.tf",
                    "line": 1,
                    "snippet": 'resource "aws_s3_bucket" "data"',
                }
            ],
        ),
        _skeptic_json(False, reasoning="no compensating control found"),
    ])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "confirmed"
    assert result.tokens_in == 200
    assert result.tokens_out == 100
    assert result.evidence[0]["kind"] == "resource"


def test_confirmed_iac_finding_surfaces_reproduction(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([
        json.dumps({
            "exploit_chain": "public bucket exposes objects [R1]",
            "evidence": [{
                "kind": "resource", "file": "infra/s3.tf", "line": 1,
                "snippet": 'resource "aws_s3_bucket" "data"',
            }],
            "reproduction": "request the bucket's public URL to list objects",
        }),
        _skeptic_json(False, reasoning="none"),
    ])

    result = verify_iac_finding(finding=finding, repo_root=str(tmp_path), llm=llm)
    assert result.verdict == "confirmed"
    assert result.verification_metadata["reproduction"] == "request the bucket's public URL to list objects"


def test_skeptic_finds_compensating_control_yields_ruled_out(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([
        _hunter_chain_json(
            "S3 bucket unencrypted",
            [
                {
                    "kind": "resource",
                    "file": "infra/s3.tf",
                    "line": 1,
                    "snippet": 'resource "aws_s3_bucket" "data"',
                }
            ],
        ),
        _skeptic_json(
            True,
            file="infra/policy.tf",
            line=3,
            snippet='Effect = "Deny", Action = "s3:*"',
            reasoning="bucket policy denies all access; data not externally readable",
        ),
    ])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "ruled_out"
    rr = result.verification_metadata["ruled_out_reason"]
    assert rr["file"] == "infra/policy.tf"
    assert "Deny" in rr["snippet"]


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_malformed_hunter_json_falls_back_safely(tmp_path):
    finding = _seed_module(tmp_path)
    # Malformed on both the first turn and the repair-retry → exhaust → fall back.
    llm = _StubLlm([
        "not json at all",
        "still not json",
    ])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "needs_verify"
    assert "hunter_schema_invalid" in result.verification_metadata.get("reason", "")
    assert len(llm.calls) == 2  # first turn + one repair, then fall back


def test_malformed_skeptic_json_falls_back_to_needs_verify(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([
        _hunter_chain_json(
            "chain",
            [
                {
                    "kind": "resource",
                    "file": "infra/s3.tf",
                    "line": 1,
                    "snippet": 'resource "aws_s3_bucket"',
                }
            ],
        ),
        "garbage",
        "still garbage",
    ])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "needs_verify"
    assert "skeptic_schema_invalid" in result.verification_metadata.get("reason", "")


def test_missing_file_does_not_crash(tmp_path):
    finding = {
        "tool": "iac_scanning",
        "check_id": "CKV_AWS_19",
        "title": "Ensure S3 bucket is encrypted",
        "severity": "high",
        "file": "does/not/exist.tf",
        "line": 1,
        "resource": "aws_s3_bucket.ghost",
    }
    llm = _StubLlm([_hunter_chain_json("", [])])

    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verdict == "possible"


def test_records_scanner_in_metadata(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([_hunter_chain_json("", [])])
    result = verify_iac_finding(
        finding=finding,
        repo_root=str(tmp_path),
        llm=llm,
    )
    assert result.verification_metadata["scanner"] == "iac_scanning"
    assert result.verification_metadata["model"] == "stub-model"
    assert result.verification_metadata["prompt_hashes"] == ["h-1"]


# ---------------------------------------------------------------------------
# Sibling-context behaviour
# ---------------------------------------------------------------------------


def test_hunter_prompt_includes_resource_and_sibling_context(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([_hunter_chain_json("", [])])

    verify_iac_finding(finding=finding, repo_root=str(tmp_path), llm=llm)

    user_msg = llm.calls[0][1]["content"]
    assert "Resource block:" in user_msg
    assert "aws_s3_bucket" in user_msg
    assert "Sibling IaC context" in user_msg
    # Sibling file content present in the prompt
    assert "policy.tf" in user_msg
    assert "aws_s3_bucket_policy" in user_msg


# ---------------------------------------------------------------------------
# Path traversal containment
# ---------------------------------------------------------------------------


def test_sibling_excerpt_refuses_traversal_outside_repo(tmp_path):
    """A `../../` file path must not exfiltrate sibling files from outside the repo."""
    from runner.verification.verifiers.iac import _collect_sibling_excerpt

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "in_repo.tf").write_text('resource "aws_s3_bucket" "ok" {}\n')

    # A sibling outside the repo that would be exposed if traversal worked.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text('SECRET = "should-never-leak"\n')

    excerpt = _collect_sibling_excerpt(str(repo_root), "../outside/anything.tf")

    assert excerpt == ""
    assert "should-never-leak" not in excerpt


def test_resource_excerpt_refuses_traversal_outside_repo(tmp_path):
    """A `../../etc/passwd`-shaped file path must not be read from disk."""
    from runner.verification.prompts.iac import _read_resource_excerpt

    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (repo_root / "ok.tf").write_text('resource "aws_s3_bucket" "ok" {}\n')

    outside = tmp_path / "outside"
    outside.mkdir()
    secret_file = outside / "passwd"
    secret_file.write_text("root:x:0:0:should-never-leak\n")

    excerpt = _read_resource_excerpt(
        str(repo_root), "../outside/passwd", line=1
    )

    assert "should-never-leak" not in excerpt
    assert "not readable" in excerpt


def test_sibling_excerpt_does_not_follow_symlinks_pointing_outside_repo(tmp_path):
    """A symlink in the parent dir pointing outside repo_root must be skipped."""
    from runner.verification.verifiers.iac import _collect_sibling_excerpt

    repo_root = tmp_path / "repo"
    module = repo_root / "infra"
    module.mkdir(parents=True)
    (module / "main.tf").write_text('resource "aws_s3_bucket" "ok" {}\n')

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.tf").write_text(
        'resource "aws_s3_bucket" "leak" { secret = "should-never-leak" }\n'
    )

    symlink = module / "leak.tf"
    try:
        symlink.symlink_to(outside / "leak.tf")
    except OSError:
        # symlink creation may be disallowed on some sandboxes; skip then.
        import pytest

        pytest.skip("symlink creation not permitted in this environment")

    excerpt = _collect_sibling_excerpt(str(repo_root), "infra/main.tf")

    assert "should-never-leak" not in excerpt


# ---------------------------------------------------------------------------
# Frontier escalation tier (dormant unless an escalation client is passed)
# ---------------------------------------------------------------------------

_GOOD_HUNTER = _hunter_chain_json(
    "bucket holds sensitive data and lacks server-side encryption",
    [{"kind": "resource", "file": "infra/s3.tf", "line": 1,
      "snippet": 'resource "aws_s3_bucket" "data"'}],
)
_GOOD_SKEPTIC = _skeptic_json(False, reasoning="no compensating control found")


def test_tier_default_stamped_and_no_escalation_by_default(tmp_path):
    finding = _seed_module(tmp_path)
    llm = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    result = verify_iac_finding(
        finding=finding, repo_root=str(tmp_path), llm=llm,
    )
    assert result.verification_metadata["tier"] == "default"
    assert "escalated" not in result.verification_metadata


def test_escalates_to_frontier_when_default_hunter_schema_fails(tmp_path):
    """Default can't produce a valid exploit chain -> the frontier tier retries."""
    finding = _seed_module(tmp_path)
    default = _StubLlm(["garbage", "still garbage"])  # both hunter turns fail
    frontier = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])

    result = verify_iac_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verdict == "confirmed"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["tier"] == "frontier"
    assert len(default.calls) == 2   # exhausted default repair budget
    assert len(frontier.calls) == 2  # frontier hunter + skeptic
    # Tokens accumulate across BOTH tiers.
    assert result.tokens_in == 400


def test_no_escalation_when_default_hunter_succeeds(tmp_path):
    finding = _seed_module(tmp_path)
    default = _StubLlm([_GOOD_HUNTER, _GOOD_SKEPTIC])
    frontier = _StubLlm([_GOOD_HUNTER])  # should never be touched

    result = verify_iac_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verdict == "confirmed"
    assert result.verification_metadata["tier"] == "default"
    assert len(frontier.calls) == 0


def test_escalation_that_also_fails_stays_needs_verify(tmp_path):
    finding = _seed_module(tmp_path)
    default = _StubLlm(["garbage", "still garbage"])
    frontier = _StubLlm(["frontier garbage", "frontier garbage 2"])

    result = verify_iac_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verdict == "needs_verify"
    assert result.verification_metadata["escalated"] is True
    assert result.verification_metadata["reason"].startswith("hunter_schema_invalid:")


def test_escalation_runs_skeptic_on_frontier_tier(tmp_path):
    """Once escalation fires, the skeptic also runs on the frontier tier."""
    finding = _seed_module(tmp_path)
    default = _StubLlm(["garbage", "still garbage"])
    # Frontier hunter succeeds but skeptic finds a compensating control.
    frontier = _StubLlm([
        _GOOD_HUNTER,
        _skeptic_json(
            True, file="infra/policy.tf", line=3,
            snippet='Effect = "Deny", Action = "s3:*"',
            reasoning="bucket policy denies all access",
        ),
    ])

    result = verify_iac_finding(
        finding=finding, repo_root=str(tmp_path),
        llm=default, escalation_llm=frontier,
    )

    assert result.verdict == "ruled_out"
    assert result.verification_metadata["tier"] == "frontier"
    assert len(frontier.calls) == 2  # hunter + skeptic, both on frontier

