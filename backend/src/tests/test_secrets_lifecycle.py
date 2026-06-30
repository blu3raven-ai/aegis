"""Contract tests for the secret-scanning lifecycle hooks.

Secrets are org-scoped but each finding is keyed per-repo so it inherits that
repo's grants, while the repo-independent secretIdentity stays in detail for
UI grouping. These tests lock the identity keying, detail mapping, and the
repo-scoped canonical_external_ref.
"""
from __future__ import annotations

from src.assets.refs import repo_ref
from src.secrets import lifecycle as lifecycle_mod
from src.secrets.lifecycle import SecretsHooks
from src.shared.lifecycle import ScanContext

hooks = SecretsHooks()


# ----- compute_identity_key -------------------------------------------------

def test_identity_key_appends_repo():
    assert hooks.compute_identity_key({"secretIdentity": "abc", "repository": "acme/api"}) == "abc::acme/api"


def test_identity_key_bare_when_no_repo():
    assert hooks.compute_identity_key({"secretIdentity": "abc"}) == "abc"
    assert hooks.compute_identity_key({"secretIdentity": "abc", "repository": "  "}) == "abc"


def test_identity_key_strips_repo_whitespace():
    assert hooks.compute_identity_key({"secretIdentity": "abc", "repository": "  acme/api  "}) == "abc::acme/api"


def test_identity_key_empty_when_unidentifiable():
    # No secretIdentity and build_secret_identity can't derive one (no org).
    assert hooks.compute_identity_key({"repository": "acme/api"}) == ""


def test_identity_key_falls_back_to_build(monkeypatch):
    monkeypatch.setattr(lifecycle_mod, "build_secret_identity", lambda raw: "BUILT")
    assert hooks.compute_identity_key({"repository": "acme/api"}) == "BUILT::acme/api"


# ----- simple hooks ---------------------------------------------------------

def test_initial_state_open():
    assert hooks.initial_state({}) == "open"


def test_should_mark_fixed_never():
    # Secrets are never auto-resolved by absence from a later scan.
    assert hooks.should_mark_fixed("abc::acme/api", {}) is False


def test_extract_repo():
    assert hooks.extract_repo({"repository": "acme/api"}) == "acme/api"
    assert hooks.extract_repo({"repository": "  acme/api  "}) == "acme/api"
    assert hooks.extract_repo({"repository": ""}) is None
    assert hooks.extract_repo({}) is None


def test_extract_severity_defaults_high():
    assert hooks.extract_severity({"severity": "low"}) == "low"
    assert hooks.extract_severity({}) == "high"


# ----- extract_detail -------------------------------------------------------

def test_extract_detail_maps_fields_and_detector_fallback():
    raw = {
        "organization": "acme", "secretIdentity": "abc", "fingerprint": "fp",
        "ruleID": "aws-access-key",  # detector missing -> falls back to ruleID
        "source": "github", "locations": [{"file": "x"}], "repository": "acme/api",
        "filePath": "config.env", "line": 12, "detectedAt": "2026-06-28T00:00:00Z",
        "secretSnippet": "AKIA…",
    }
    d = hooks.extract_detail(raw)
    assert d["detector"] == "aws-access-key"
    assert d["secretIdentity"] == "abc"
    assert d["repository"] == "acme/api"
    assert d["line"] == 12
    assert d["locations"] == [{"file": "x"}]
    # Defaults for absent optionals.
    assert d["commit"] == ""
    assert d["raw"] == {}
    assert d["aiReasoning"] is None


def test_extract_detail_prefers_detector_over_rule_id():
    d = hooks.extract_detail({"detector": "trufflehog-aws", "ruleID": "aws-access-key"})
    assert d["detector"] == "trufflehog-aws"


def test_extract_detail_carries_verification_fields_when_present():
    # The runner verifier writes a verdict + rotation runbook onto the raw
    # finding; these must survive extract_detail so upsert_finding can promote
    # them to the typed columns (they were previously dropped by the allowlist).
    raw = {
        "secretIdentity": "abc", "repository": "acme/api",
        "verdict": "confirmed",
        "evidence": {"why": "key is live"},
        "exploit_chain": ["step1", "step2"],
        "verification_metadata": {"model": "argus"},
        "recommended_fix": {
            "kind": "rotation",
            "title": "Rotate the AWS key",
            "steps": ["Revoke the key", "Issue a new key"],
        },
    }
    d = hooks.extract_detail(raw)
    assert d["verdict"] == "confirmed"
    assert d["evidence"] == {"why": "key is live"}
    assert d["exploit_chain"] == ["step1", "step2"]
    assert d["verification_metadata"] == {"model": "argus"}
    assert d["recommended_fix"]["kind"] == "rotation"
    assert d["recommended_fix"]["title"] == "Rotate the AWS key"


def test_extract_detail_omits_verification_fields_when_absent():
    # Unverified findings keep a clean detail — no null verification keys.
    d = hooks.extract_detail({"secretIdentity": "abc", "repository": "acme/api"})
    for key in ("verdict", "evidence", "exploit_chain", "verification_metadata", "recommended_fix"):
        assert key not in d


# ----- canonical_external_ref ----------------------------------------------

def _ctx(source_type):
    return ScanContext(tool="secret_scanning", org="acme", run_id="r1", source_type=source_type)


def test_external_ref_scopes_to_repo():
    ctx = _ctx("github")
    ref, kind = hooks.canonical_external_ref(ctx, {"repository": "acme/api"})
    # name drops the owner prefix; org comes from the (normalized) context.
    assert ref == repo_ref("github", ctx.org, "api")
    assert kind == "repo"


def test_external_ref_none_without_repo():
    assert hooks.canonical_external_ref(_ctx("github"), {"repository": ""}) is None


def test_external_ref_none_without_source_type():
    assert hooks.canonical_external_ref(_ctx(None), {"repository": "acme/api"}) is None
