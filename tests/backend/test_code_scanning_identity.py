"""SAST finding identity — must be stable across line drift.

Regression for the re-scan bug: when an unrelated edit shifted a finding's line
number, the old line-based identity key changed, so the previous finding looked
"vanished" (auto-fixed) and the moved result was inserted as new — losing triage
state and resetting SLA clocks. Identity now keys on a snippet fingerprint.
"""
from __future__ import annotations

from src.code_scanning.ingest import (
    code_finding_identity,
    finding_identity_key,
    identity_key_from_finding,
    repo_relative_path,
)
from src.code_scanning.lifecycle import code_scanning_hooks


def _raw(start_line: int, snippet: str, *, rule="py.sqli", path="app/db.py"):
    return {
        "repo_full_name": "acme/api",
        "file_path": path,
        "rule_id": rule,
        "start_line": start_line,
        "snippet": snippet,
    }


def test_identical_snippets_at_different_lines_have_different_keys():
    """Two identical vulnerable patterns at different locations must not collapse."""
    line_10 = code_scanning_hooks.compute_identity_key(_raw(10, "os.system(user_input)"))
    line_42 = code_scanning_hooks.compute_identity_key(_raw(42, "os.system(user_input)"))
    assert line_10 != line_42


def test_identity_changes_when_line_shifts():
    """A finding that moves to a new line gets a new key (acceptable re-key vs data loss)."""
    before = code_scanning_hooks.compute_identity_key(_raw(12, "query(f'... {user_id}')"))
    after = code_scanning_hooks.compute_identity_key(_raw(52, "query(f'... {user_id}')"))
    assert before != after


def test_identity_distinguishes_distinct_snippets():
    """Two different sinks for the same rule in the same file stay separate."""
    a = code_scanning_hooks.compute_identity_key(_raw(12, "query(f'... {user_id}')"))
    b = code_scanning_hooks.compute_identity_key(_raw(30, "query(f'... {account}')"))
    assert a != b


def test_identity_normalizes_indentation():
    """Reindentation at the same line must not re-key the finding."""
    a = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "    do_thing(x)")
    b = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "do_thing(x)")
    assert a == b


def test_identity_falls_back_to_line_without_snippet():
    """No snippet → keep the legacy line-based key (no needless churn)."""
    k = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "")
    assert k == "acme/api:app/db.py:py.sqli:12"
    # distinct lines remain distinct when there is nothing to fingerprint
    other = code_finding_identity("acme/api", "app/db.py", "py.sqli", 13, "")
    assert k != other


def test_identity_escapes_colons_in_components():
    k = code_finding_identity("acme/a:b", "x.py", "r", 1, "")
    assert k == "acme/a%3Ab:x.py:r:1"


def test_helpers_delegate_to_code_finding_identity():
    expected = code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "sink(x)")
    assert finding_identity_key("acme/api", "app/db.py", "py.sqli", 12, "sink(x)") == expected
    assert identity_key_from_finding(_raw(12, "sink(x)")) == expected


def test_extract_detail_carries_recommended_fix():
    # The remediation panel needs recommended_fix persisted; extract_detail must
    # pass it through. It is additive — it never hides a finding.
    raw = _raw(12, "sink(x)")
    raw["recommended_fix"] = {"kind": "code_patch", "diff": "--- a\n+++ b\n"}
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["recommended_fix"] == {"kind": "code_patch", "diff": "--- a\n+++ b\n"}


def test_extract_detail_omits_recommended_fix_when_absent():
    detail = code_scanning_hooks.extract_detail(_raw(12, "sink(x)"))
    assert "recommended_fix" not in detail


def test_extract_detail_carries_verification_fields():
    # The verification panel needs verdict/evidence/metadata persisted; the
    # grounding gate in finding_queries decides whether a ruled_out may hide.
    raw = _raw(12, "sink(x)")
    raw["verdict"] = "ruled_out"
    raw["evidence"] = [{"kind": "code", "file": "app/db.py", "line": 12}]
    raw["verification_metadata"] = {"ruled_out_reason": {"file": "app/guard.py"}}
    detail = code_scanning_hooks.extract_detail(raw)
    assert detail["verdict"] == "ruled_out"
    assert detail["evidence"] == [{"kind": "code", "file": "app/db.py", "line": 12}]
    assert detail["verification_metadata"] == {"ruled_out_reason": {"file": "app/guard.py"}}


def test_extract_detail_omits_verdict_when_unverified():
    detail = code_scanning_hooks.extract_detail(_raw(12, "sink(x)"))
    assert "verdict" not in detail


def test_repo_relative_path_strips_checkout_prefix():
    assert repo_relative_path("acme-repo/_checkout/app/db.py") == "app/db.py"


def test_repo_relative_path_strips_temp_and_checkout_prefix():
    assert (
        repo_relative_path("/tmp/tmp.abc123/acme-repo/_checkout/server.py")
        == "server.py"
    )


def test_repo_relative_path_reanchors_on_last_checkout():
    # A repo that legitimately nests a "_checkout/" dir keeps its real subtree.
    assert (
        repo_relative_path("repo/_checkout/pkg/_checkout/main.go")
        == "main.go"
    )


def test_repo_relative_path_leaves_clean_path_untouched():
    assert repo_relative_path("src/handlers/users.py") == "src/handlers/users.py"


def test_ingest_stores_repo_relative_path_and_matching_identity(tmp_path):
    from src.code_scanning.ingest import ingest_findings_jsonl

    findings_path = tmp_path / "findings.jsonl"
    findings_path.write_text(
        '{"rule_id": "py.sqli", "repo_full_name": "acme/api", '
        '"file_path": "acme-repo/_checkout/app/db.py", "start_line": 12, '
        '"snippet": "query(x)", "severity": "high", "engine": "semgrep"}\n'
    )

    [finding] = ingest_findings_jsonl(findings_path)

    # Stored path is repo-relative — no clone-dir scaffolding leaks through.
    assert finding["file_path"] == "app/db.py"
    # Identity + detail derive from the same cleaned path, so a re-scan with a
    # clean-path runner keeps the finding's identity (and its triage state).
    key = code_scanning_hooks.compute_identity_key(finding)
    assert "_checkout" not in key
    assert key == code_finding_identity("acme/api", "app/db.py", "py.sqli", 12, "query(x)")
    assert code_scanning_hooks.extract_detail(finding)["filePath"] == "app/db.py"
