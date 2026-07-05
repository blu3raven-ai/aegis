"""Coverage for the notification emitter's content logic.

The pure helpers decide the severity and label shown in every alert across all
scanner types (a wrong fallback mislabels a critical alert as low), and
notify_new_critical_findings builds the title/severity/message users actually
see. Side effects (store + SSE) are stubbed so only the content logic is pinned.
"""
from __future__ import annotations

import pytest

from src.notifications import emitter
from src.notifications.emitter import (
    _finding_label,
    _finding_severity,
    _tool_to_settings_path,
    notify_new_critical_findings,
)


# ── _tool_to_settings_path ───────────────────────────────────────────────────

@pytest.mark.parametrize(
    "tool,expected",
    [
        ("dependencies_scanning", "dependencies"),
        ("code_scanning", "code"),
        ("secret_scanning", "secrets"),
        ("container_scanning", "containers"),
        ("iac_scanning", "iac-security"),
        ("unknown_tool", "unknown_tool"),  # passthrough
    ],
)
def test_tool_to_settings_path(tool, expected):
    assert _tool_to_settings_path(tool) == expected


# ── _finding_severity ────────────────────────────────────────────────────────

def test_severity_prefers_security_advisory():
    f = {"security_advisory": {"severity": "critical"}, "severity": "low"}
    assert _finding_severity(f) == "critical"


def test_severity_falls_back_to_severity_field():
    assert _finding_severity({"severity": "high"}) == "high"


def test_severity_secret_default_high():
    # A secret finding (detector present) with no severity defaults to high.
    assert _finding_severity({"detector": "aws-key"}) == "high"


def test_severity_verified_secret_is_critical():
    f = {
        "secretIdentity": "x",
        "classificationHistory": [{"value": "verified_secret"}],
    }
    assert _finding_severity(f) == "critical"


def test_severity_unknown_is_empty():
    assert _finding_severity({"foo": "bar"}) == ""


# ── _finding_label ───────────────────────────────────────────────────────────

def test_label_prefers_package_name():
    assert _finding_label({"dependency": {"package": {"name": "left-pad"}}}) == "left-pad"


def test_label_falls_back_to_package_name_field():
    assert _finding_label({"package_name": "lodash"}) == "lodash"


def test_label_uses_rule_name_for_sast():
    assert _finding_label({"rule_name": "B608"}) == "B608"


def test_label_uses_detector_for_secrets():
    assert _finding_label({"detector": "GitHubToken"}) == "GitHubToken"


def test_label_empty_when_nothing_identifiable():
    assert _finding_label({"foo": "bar"}) == ""


# ── notify_new_critical_findings (content builder) ───────────────────────────

@pytest.fixture
def captured(monkeypatch):
    calls = {}
    monkeypatch.setattr(emitter, "_get_active_user_ids", lambda: ["u1"])
    monkeypatch.setattr(emitter, "_publish_notification_sse", lambda *a, **k: None)

    def _capture(user_ids, **kwargs):
        calls.update(kwargs)
        calls["user_ids"] = user_ids

    monkeypatch.setattr(emitter, "emit_notification_to_all", _capture)
    return calls


def test_no_critical_or_high_does_not_emit(captured):
    notify_new_critical_findings("code_scanning", "acme-org", [{"severity": "low"}])
    assert captured == {}  # early return — nothing emitted


def test_multiple_criticals_title_and_severity(captured):
    findings = [{"severity": "critical"}, {"severity": "critical"}]
    notify_new_critical_findings("code_scanning", "acme-org", findings)
    assert captured["severity"] == "critical"
    assert captured["title"] == "2 new critical findings"
    assert captured["context"]["count"] == 2


def test_single_critical_is_singular(captured):
    notify_new_critical_findings("code_scanning", "acme-org", [{"severity": "critical"}])
    assert captured["title"] == "1 new critical finding"


def test_critical_and_high_combined_title(captured):
    findings = [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}]
    notify_new_critical_findings("code_scanning", "acme-org", findings)
    assert captured["title"] == "1 critical + 2 high findings"
    assert captured["severity"] == "critical"  # any critical → critical
    assert captured["context"]["count"] == 3


def test_high_only_is_warning_severity(captured):
    notify_new_critical_findings("code_scanning", "acme-org", [{"severity": "high"}])
    assert captured["severity"] == "warning"
    assert captured["title"] == "1 new high finding"


def test_top_finding_label_in_message(captured):
    findings = [{"severity": "critical", "package_name": "log4j"}]
    notify_new_critical_findings("dependencies_scanning", "acme-org", findings)
    assert "log4j" in captured["message"]
    assert "acme-org" in captured["message"]
    assert captured["link"] == "/findings?scanner=dependencies_scanning"
