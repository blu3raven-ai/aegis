"""Pure-function coverage for findings/service.py — cursor codec, secret redaction,
and the finding-detail transforms that shape the API response. No DB required."""
from __future__ import annotations

import pytest

from src.findings.service import (
    _advisory_references,
    _as_int,
    _decode_cursor,
    _detail_cwe,
    _encode_cursor,
    _first_line,
    _patched_version_str,
    _sast_title,
    _scrub_known_secrets,
    _secret_type_label,
)


# --- pagination cursor codec ---

def test_cursor_round_trips():
    payload = {"id": "abc", "score": 7.5, "band": "act"}
    assert _decode_cursor(_encode_cursor(payload)) == payload


def test_cursor_is_url_safe_and_unpadded():
    token = _encode_cursor({"k": "v" * 20})
    assert "=" not in token and "/" not in token and "+" not in token


def test_decode_rejects_garbage_cursor():
    with pytest.raises(ValueError, match="invalid cursor"):
        _decode_cursor("!!!not-base64!!!")


# --- secret redaction (security-relevant) ---

@pytest.mark.parametrize("secret", [
    "AKIAIOSFODNN7EXAMPLE",                       # AWS access key id
    "sk-abcdefghijklmnopqrstuvwxyz012345",        # OpenAI/Stripe secret key
    "ghp_" + "a" * 36,                            # GitHub token
    "xoxb-1234567890-abcdefghijkl",               # Slack token
    "AIza" + "b" * 35,                            # Google API key
])
def test_scrub_masks_known_credential_formats(secret):
    scrubbed = _scrub_known_secrets(f"leaked here: {secret} end")
    assert secret not in scrubbed and "redacted-secret" in scrubbed


def test_scrub_leaves_ordinary_text_untouched():
    text = "just a normal config line = 42"
    assert _scrub_known_secrets(text) == text


# --- secret type label ---

def test_secret_type_label_appends_secret_when_not_already_credentialish():
    assert _secret_type_label({"detector": "aws"}) == "aws secret"


def test_secret_type_label_appends_secret_unless_word_present():
    # 'github-pat' has no credential keyword → gets the ' secret' suffix
    assert _secret_type_label({"detector": "github-pat"}) == "github pat secret"
    # 'api-key' already contains 'key' → left as-is
    assert _secret_type_label({"detector": "api-key"}) == "api key"
    assert _secret_type_label({"detector": "auth-token"}) == "auth token"  # 'token' present


def test_secret_type_label_none_when_no_detector():
    assert _secret_type_label({}) is None
    assert _secret_type_label({"detector": "  "}) is None


# --- title / cwe / version transforms ---

def test_first_line_trims_and_caps():
    assert _first_line("  hello world\nsecond line  ") == "hello world"
    assert _first_line("x" * 200, cap=10) == "x" * 10


def test_sast_title_prefers_ai_then_message_then_rule():
    class F:
        title = "raw"
        identity_key = "k"
    assert _sast_title(F(), {"verification_metadata": {"title": "AI vector"}}) == "AI vector"
    assert _sast_title(F(), {"message": "semgrep msg"}) == "semgrep msg"
    assert _sast_title(F(), {"ruleName": "sqli-rule"}) == "sqli-rule"
    # a rule id carrying a clone path is rejected in favor of the stored title
    assert _sast_title(F(), {"ruleId": "/workspace/x/rule"}) == "raw"


def test_detail_cwe_handles_list_string_and_missing():
    assert _detail_cwe({"cwe": ["CWE-89", "CWE-79"]}) == "CWE-89"
    assert _detail_cwe({"cwe": "CWE-22"}) == "CWE-22"
    assert _detail_cwe({"cwe": []}) is None
    assert _detail_cwe({}) is None


def test_patched_version_str_handles_string_and_dict_forms():
    assert _patched_version_str("1.2.3") == "1.2.3"
    assert _patched_version_str({"identifier": "2.0.0"}) == "2.0.0"
    assert _patched_version_str({"other": "x"}) is None
    assert _patched_version_str(None) is None


def test_as_int_coerces_and_rejects():
    assert _as_int("42") == 42
    assert _as_int(7) == 7
    assert _as_int("not-a-number") is None
    assert _as_int(None) is None


def test_advisory_references_extracts_urls_from_mixed_shapes():
    raw = ["https://a.example", {"url": "https://b.example"}, {"noturl": "x"}, "https://c.example"]
    refs = _advisory_references(raw)
    assert "https://a.example" in refs and "https://b.example" in refs and "https://c.example" in refs
