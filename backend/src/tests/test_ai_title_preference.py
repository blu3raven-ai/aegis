"""_sast_title prefers an AI-authored verification title over semgrep's message."""
from types import SimpleNamespace

from src.findings.service import _sast_title


def _finding():
    return SimpleNamespace(title="raw/clone/path:rule", identity_key="id")


def test_prefers_ai_title_when_present():
    detail = {
        "message": "Detected string concatenation with a non-literal variable",
        "verification_metadata": {"title": "SQL injection in report filter reads other tenants' rows"},
    }
    assert _sast_title(_finding(), detail) == "SQL injection in report filter reads other tenants' rows"


def test_falls_back_to_semgrep_message_without_ai_title():
    detail = {"message": "Detected string concatenation with a non-literal variable"}
    assert _sast_title(_finding(), detail) == "Detected string concatenation with a non-literal variable"
