"""Tests for repo_html_url propagation through the code scanning pipeline.

Covers: lifecycle extract_detail, storage _finding_to_code_scanning_dict.
The scanner-level test is in scanners/code-scanning/scripts/test-normalize.sh.
"""
from src.code_scanning.lifecycle import CodeScanningHooks
from src.storage import _finding_to_code_scanning_dict


_hooks = CodeScanningHooks()


# ---------------------------------------------------------------------------
# extract_detail — saves repoHtmlUrl into the stored detail blob
# ---------------------------------------------------------------------------

def test_extract_detail_saves_repo_html_url():
    raw = {
        "rule_id": "python.injection",
        "rule_name": "Injection",
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
        "snippet": "subprocess.run(cmd)",
        "message": "Dangerous call",
        "category": "security",
        "cwe": ["CWE-78"],
        "confidence": "high",
        "fix_suggestion": "Use shlex.escape()",
        "repo_html_url": "https://github.com/acme-org/example-repo",
        "language": "python",
        "file_class": "source",
    }
    detail = _hooks.extract_detail(raw)
    assert detail["repoHtmlUrl"] == "https://github.com/acme-org/example-repo"


def test_extract_detail_empty_repo_html_url_when_missing():
    raw = {
        "rule_id": "python.injection",
        "rule_name": "Injection",
        "file_path": "src/app.py",
        "start_line": 10,
        "end_line": 10,
        "snippet": "",
        "message": "msg",
        "category": "security",
        "cwe": [],
        "confidence": "medium",
        "language": "python",
        "file_class": "source",
    }
    detail = _hooks.extract_detail(raw)
    assert detail.get("repoHtmlUrl") == ""


# ---------------------------------------------------------------------------
# _finding_to_code_scanning_dict — reads repoHtmlUrl back from detail
# ---------------------------------------------------------------------------

class _MockFinding:
    """Minimal stand-in for the Finding ORM model."""
    def __init__(self, detail, *, org: str = "acme-org", repo: str = "example-repo"):
        self.state = "open"
        self.first_seen_at = None
        self.fixed_at = None
        self.org = org
        self.repo = repo
        self.severity = "high"
        self.detail = detail


def test_storage_exposes_repo_html_url():
    detail = {
        "ruleId": "python.injection",
        "ruleName": "Injection",
        "filePath": "src/app.py",
        "startLine": 10,
        "endLine": 10,
        "snippet": "subprocess.run(cmd)",
        "message": "Dangerous call",
        "category": "security",
        "cwe": ["CWE-78"],
        "confidence": "high",
        "fixSuggestion": "Use shlex.escape()",
        "repoHtmlUrl": "https://github.com/acme-org/example-repo",
        "language": "python",
        "fileClass": "source",
    }
    result = _finding_to_code_scanning_dict(_MockFinding(detail), decision=None)
    assert result["repo_html_url"] == "https://github.com/acme-org/example-repo"


def test_storage_repo_html_url_empty_when_not_stored():
    """Old findings in DB that predate the repoHtmlUrl field return empty string."""
    detail = {
        "ruleId": "python.injection",
        "ruleName": "Injection",
        "filePath": "src/app.py",
        "startLine": 10,
        "endLine": 10,
        "snippet": "",
        "message": "msg",
        "category": "security",
        "cwe": [],
        "confidence": "medium",
        "language": "python",
        "fileClass": "source",
    }
    result = _finding_to_code_scanning_dict(_MockFinding(detail), decision=None)
    assert result["repo_html_url"] == ""


# ---------------------------------------------------------------------------
# repo_full_name — combines org + repo so the Org column renders correctly
# ---------------------------------------------------------------------------

_MINIMAL_DETAIL = {
    "ruleId": "r",
    "ruleName": "R",
    "filePath": "src/app.py",
    "startLine": 1,
    "endLine": 1,
    "snippet": "",
    "message": "",
    "category": "security",
    "cwe": [],
    "confidence": "high",
    "language": "python",
    "fileClass": "source",
}


def test_repo_full_name_combines_org_and_repo():
    result = _finding_to_code_scanning_dict(
        _MockFinding(_MINIMAL_DETAIL, org="acme-org", repo="example-repo"),
        decision=None,
    )
    assert result["repo_full_name"] == "acme-org/example-repo"


def test_repo_full_name_falls_back_to_repo_when_org_missing():
    f = _MockFinding(_MINIMAL_DETAIL, org="", repo="example-repo")
    result = _finding_to_code_scanning_dict(f, decision=None)
    assert result["repo_full_name"] == "example-repo"


def test_repo_full_name_empty_string_when_both_missing():
    f = _MockFinding(_MINIMAL_DETAIL, org="", repo="")
    result = _finding_to_code_scanning_dict(f, decision=None)
    assert result["repo_full_name"] == ""
