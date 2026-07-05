"""Tests for deterministic IaC config-hardening patches (no LLM)."""
from __future__ import annotations

from pathlib import Path

import yaml

from runner.scanners.iac import remediation
from runner.scanners.iac.remediation import (
    CHECK_ID_TEMPLATES,
    attach_iac_fixes,
    build_iac_fix,
    recheck_iac,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _checkov_payload(failed_ids, *, parse_errors: int = 0) -> dict:
    """A minimal checkov-shaped JSON payload for stubbing the re-scan."""
    return {
        "results": {
            "failed_checks": [{"check_id": cid} for cid in failed_ids],
        },
        "summary": {"parsing_errors": parse_errors},
    }


def _stub_recheck(monkeypatch, payload):
    """Stub the single-file checkov shell-out with a controlled payload."""
    monkeypatch.setattr(
        remediation, "_run_checkov_on_text", lambda block, ext: payload
    )


def _seed_pab(repo: Path) -> dict:
    (repo / "infra").mkdir(parents=True, exist_ok=True)
    (repo / "infra" / "pab.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        "  bucket                  = aws_s3_bucket.data.id\n"
        "  block_public_acls       = false\n"
        "  block_public_policy     = false\n"
        "  ignore_public_acls      = false\n"
        "  restrict_public_buckets = false\n"
        "}\n"
    )
    return {
        "tool": "iac_scanning",
        "check_id": "CKV_AWS_53",
        "title": "Ensure S3 bucket has block public ACLs enabled",
        "severity": "high",
        "file": "infra/pab.tf",
        "line": 1,
        "resource": "aws_s3_bucket_public_access_block.data",
    }


def _seed_bucket(repo: Path) -> dict:
    (repo / "infra").mkdir(parents=True, exist_ok=True)
    (repo / "infra" / "s3.tf").write_text(
        'resource "aws_s3_bucket" "data" {\n'
        '  bucket = "acme-org-data"\n'
        "}\n"
    )
    return {
        "tool": "iac_scanning",
        "check_id": "CKV_AWS_19",
        "title": "Ensure S3 bucket is encrypted at rest",
        "severity": "high",
        "file": "infra/s3.tf",
        "line": 1,
        "resource": "aws_s3_bucket.data",
    }


def _seed_deployment(repo: Path) -> dict:
    (repo / "k8s").mkdir(parents=True, exist_ok=True)
    (repo / "k8s" / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: api\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: app\n"
        "          image: nginx:1.27\n"
        "          securityContext:\n"
        "            privileged: true\n"
    )
    return {
        "tool": "iac_scanning",
        "check_id": "CKV_K8S_16",
        "title": "Container should not be privileged",
        "severity": "high",
        "file": "k8s/deploy.yaml",
        "line": 1,
        "resource": "Deployment.default.api",
    }


def _braces_balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if depth < 0:
            return False
    return depth == 0


# ---------------------------------------------------------------------------
# Unmapped check_id -> no fix (never guess)
# ---------------------------------------------------------------------------


def test_unmapped_check_id_returns_none(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = _seed_bucket(tmp_path)
    finding["check_id"] = "CKV_AWS_999"
    assert build_iac_fix(finding, str(tmp_path)) is None


def test_missing_check_id_returns_none(tmp_path):
    finding = _seed_bucket(tmp_path)
    finding["check_id"] = ""
    assert build_iac_fix(finding, str(tmp_path)) is None


# ---------------------------------------------------------------------------
# Mapped check_ids -> config_patch shape
# ---------------------------------------------------------------------------


def test_s3_pab_flag_fix_shape(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = _seed_pab(tmp_path)

    fix = build_iac_fix(finding, str(tmp_path))
    assert fix is not None
    assert fix["kind"] == "config_patch"
    assert fix["source"] == "deterministic"
    assert fix["filePath"] == "infra/pab.tf"
    assert fix["resource"] == "aws_s3_bucket_public_access_block.data"
    assert "block_public_acls       = false" in fix["before"]
    assert "block_public_acls       = true" in fix["after"]
    # Only the targeted flag is flipped; siblings are untouched.
    assert "block_public_policy     = false" in fix["after"]
    assert "CKV_AWS_53" in fix["rationale"]
    assert fix["validated"] is True


def test_s3_sse_fix_shape(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = _seed_bucket(tmp_path)

    fix = build_iac_fix(finding, str(tmp_path))
    assert fix is not None
    assert fix["kind"] == "config_patch"
    assert "server_side_encryption_configuration" not in fix["before"]
    assert "server_side_encryption_configuration" in fix["after"]
    assert 'sse_algorithm = "aws:kms"' in fix["after"]
    assert _braces_balanced(fix["after"])


def test_k8s_security_context_fix_shape(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = _seed_deployment(tmp_path)

    fix = build_iac_fix(finding, str(tmp_path))
    assert fix is not None
    assert fix["kind"] == "config_patch"
    assert fix["resource"] == "Deployment.default.api"
    parsed = yaml.safe_load(fix["after"])
    container = parsed["spec"]["template"]["spec"]["containers"][0]
    assert container["securityContext"]["privileged"] is False


def test_every_mapped_check_produces_config_patch(tmp_path, monkeypatch):
    # Re-scan stub clears the offending check for all templates.
    _stub_recheck(monkeypatch, _checkov_payload([]))

    tf_bucket = _seed_bucket(tmp_path)
    tf_pab = _seed_pab(tmp_path)
    k8s = _seed_deployment(tmp_path)

    bases = {
        "CKV_AWS_19": tf_bucket,
        "CKV_AWS_145": tf_bucket,
        "CKV_AWS_53": tf_pab,
        "CKV_AWS_54": tf_pab,
        "CKV_AWS_55": tf_pab,
        "CKV_AWS_56": tf_pab,
        "CKV_K8S_16": k8s,
        "CKV_K8S_20": k8s,
        "CKV_K8S_22": k8s,
        "CKV_K8S_23": k8s,
    }
    assert set(bases) == set(CHECK_ID_TEMPLATES)

    for check_id, base in bases.items():
        finding = dict(base)
        finding["check_id"] = check_id
        fix = build_iac_fix(finding, str(tmp_path))
        assert fix is not None, check_id
        assert fix["kind"] == "config_patch", check_id
        assert fix["source"] == "deterministic", check_id
        assert fix["before"] and fix["after"], check_id
        assert fix["after"] != fix["before"], check_id
        assert check_id in fix["rationale"], check_id


def test_k8s_after_blocks_are_well_formed_yaml(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    base = _seed_deployment(tmp_path)

    for check_id, key, expected in [
        ("CKV_K8S_20", "allowPrivilegeEscalation", False),
        ("CKV_K8S_22", "readOnlyRootFilesystem", True),
        ("CKV_K8S_23", "runAsNonRoot", True),
    ]:
        finding = dict(base)
        finding["check_id"] = check_id
        fix = build_iac_fix(finding, str(tmp_path))
        assert fix is not None, check_id
        parsed = yaml.safe_load(fix["after"])  # must parse
        sc = parsed["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        assert sc[key] is expected, check_id


# ---------------------------------------------------------------------------
# Safety: don't guess non-literal values, don't touch the working tree
# ---------------------------------------------------------------------------


def test_non_literal_attr_is_not_guessed(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    (tmp_path / "infra").mkdir(parents=True, exist_ok=True)
    (tmp_path / "infra" / "pab.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "data" {\n'
        "  bucket            = aws_s3_bucket.data.id\n"
        "  block_public_acls = var.block_acls\n"
        "}\n"
    )
    finding = {
        "check_id": "CKV_AWS_53",
        "file": "infra/pab.tf",
        "line": 1,
        "resource": "aws_s3_bucket_public_access_block.data",
    }
    # Value is a variable, not a literal false — refuse rather than rewrite it.
    assert build_iac_fix(finding, str(tmp_path)) is None


def test_build_fix_does_not_modify_working_tree(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = _seed_pab(tmp_path)
    src = tmp_path / "infra" / "pab.tf"
    before = src.read_text()

    build_iac_fix(finding, str(tmp_path))
    assert src.read_text() == before  # suggestion only — no file write


def test_unreadable_file_returns_none(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = {
        "check_id": "CKV_AWS_53",
        "file": "infra/missing.tf",
        "line": 1,
        "resource": "aws_s3_bucket_public_access_block.data",
    }
    assert build_iac_fix(finding, str(tmp_path)) is None


def test_path_traversal_file_returns_none(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    finding = {
        "check_id": "CKV_AWS_53",
        "file": "../../etc/passwd",
        "line": 1,
        "resource": "aws_s3_bucket_public_access_block.data",
    }
    assert build_iac_fix(finding, str(tmp_path)) is None


# ---------------------------------------------------------------------------
# recheck_iac honesty
# ---------------------------------------------------------------------------


def test_recheck_true_when_check_cleared(tmp_path, monkeypatch):
    # Patched block no longer fails the target; remaining checks are in baseline.
    _stub_recheck(monkeypatch, _checkov_payload(["CKV_AWS_54", "CKV_AWS_55"]))
    assert recheck_iac(
        "block { }",
        "CKV_AWS_53",
        str(tmp_path),
        baseline_check_ids=frozenset({"CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55"}),
    )


def test_recheck_false_when_target_still_fails(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload(["CKV_AWS_53"]))
    assert not recheck_iac(
        "block { }",
        "CKV_AWS_53",
        str(tmp_path),
        baseline_check_ids=frozenset({"CKV_AWS_53"}),
    )


def test_recheck_false_when_new_check_fires(tmp_path, monkeypatch):
    # A check appears that was NOT in the original block's baseline -> regression.
    _stub_recheck(monkeypatch, _checkov_payload(["CKV_AWS_777"]))
    assert not recheck_iac(
        "block { }",
        "CKV_AWS_53",
        str(tmp_path),
        baseline_check_ids=frozenset({"CKV_AWS_53"}),
    )


def test_recheck_false_on_parse_error(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([], parse_errors=1))
    assert not recheck_iac("garbage", "CKV_AWS_53", str(tmp_path))


def test_recheck_false_when_checkov_unavailable(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, None)
    assert not recheck_iac("block { }", "CKV_AWS_53", str(tmp_path))


def test_recheck_accepts_per_framework_list_payload(tmp_path, monkeypatch):
    # checkov emits a list when multiple frameworks match; summarize must cope.
    _stub_recheck(monkeypatch, [_checkov_payload([])])
    assert recheck_iac("block { }", "CKV_AWS_53", str(tmp_path))


def test_fix_surfaced_with_validated_false_when_checkov_unavailable(
    tmp_path, monkeypatch
):
    _stub_recheck(monkeypatch, None)  # checkov not runnable in this env
    finding = _seed_pab(tmp_path)

    fix = build_iac_fix(finding, str(tmp_path))
    assert fix is not None  # deterministic fix is still surfaced
    assert fix["validated"] is False


def test_validated_reflects_failing_recheck(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload(["CKV_AWS_53"]))  # not cleared
    finding = _seed_pab(tmp_path)

    fix = build_iac_fix(finding, str(tmp_path))
    assert fix is not None
    assert fix["validated"] is False


# ---------------------------------------------------------------------------
# attach_iac_fixes (scanner emit hook)
# ---------------------------------------------------------------------------


def test_attach_sets_fix_on_mapped_and_skips_unmapped(tmp_path, monkeypatch):
    _stub_recheck(monkeypatch, _checkov_payload([]))
    mapped = _seed_pab(tmp_path)
    unmapped = dict(mapped)
    unmapped["check_id"] = "CKV_AWS_999"

    out = attach_iac_fixes([mapped, unmapped], str(tmp_path))
    assert out[0]["recommended_fix"]["kind"] == "config_patch"
    assert "recommended_fix" not in out[1]


def test_attach_baseline_validates_multi_check_resource(tmp_path, monkeypatch):
    # All four PAB flags fail on the same resource. After fixing one, the other
    # three remain — they are baseline, not a regression, so validated stays True.
    _stub_recheck(
        monkeypatch,
        _checkov_payload(["CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"]),
    )
    base = _seed_pab(tmp_path)
    findings = []
    for cid in ("CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"):
        f = dict(base)
        f["check_id"] = cid
        findings.append(f)

    out = attach_iac_fixes(findings, str(tmp_path))
    assert out[0]["recommended_fix"]["validated"] is True


def test_attach_swallows_per_finding_errors(tmp_path, monkeypatch):
    def _boom(*a, **kw):
        raise RuntimeError("template blew up")

    # A bug in per-finding fix generation must not break the whole scan: attach
    # logs and skips, leaving the finding without a recommended_fix.
    monkeypatch.setattr(remediation, "build_iac_fix", _boom)
    finding = _seed_pab(tmp_path)

    out = attach_iac_fixes([finding], str(tmp_path))
    assert "recommended_fix" not in out[0]


def test_extract_tf_block_ignores_braces_in_strings_and_comments():
    # A `}` inside a string literal or comment must not prematurely balance the
    # block — otherwise the extracted before/after gets truncated.
    lines = [
        'resource "aws_s3_bucket" "b" {',
        '  desc = "a close } brace in a string"  # and a } in a comment',
        '  acl  = "private"',
        "}",
    ]
    block = remediation._extract_tf_block(lines, 1)
    assert block == "\n".join(lines)  # full block, not truncated at line 2
