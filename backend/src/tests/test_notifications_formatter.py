"""Unit tests for notifications.formatter.

Pure-function module — every test here is deterministic and DB-free. The goal
is to lock the dispatch-time shape expected by each sender so a future refactor
can't silently break the format that downstream destinations have implemented
against.
"""
from __future__ import annotations

from src.notifications.formatter import (
    _escape_mrkdwn,
    _event_title,
    _payload_fields,
    _summary_line,
    format_for_email,
    format_for_slack,
    format_for_webhook,
)




def _finding_created_event() -> dict:
    return {
        "event_type": "finding.created",
        "event_id": "ev-1",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {
            "severity": "high",
            "tool": "trivy",
            "title": "CVE-2025-1234 in lodash",
        },
    }


def _severity_changed_event() -> dict:
    return {
        "event_type": "finding.severity_changed",
        "event_id": "ev-2",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {
            "old_severity": "medium",
            "new_severity": "critical",
            "title": "CVE-2025-9999",
        },
    }


def _exploit_event() -> dict:
    return {
        "event_type": "intel.exploit_availability_changed",
        "event_id": "ev-3",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {
            "cve_id": "CVE-2025-1111",
            "new_availability": "public",
        },
    }


def _anomaly_event() -> dict:
    return {
        "event_type": "intel.anomaly_detected",
        "event_id": "ev-4",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {
            "scanner_type": "sast",
            "multiplier": 3.5,
            "window_count": 42,
        },
    }




def test_summary_line_finding_created_includes_title_and_severity():
    out = _summary_line(_finding_created_event())
    assert "[acme-org]" in out
    assert "New finding" in out
    assert "CVE-2025-1234 in lodash" in out
    assert "(high)" in out


def test_summary_line_severity_changed_uses_event_title():
    out = _summary_line(_severity_changed_event())
    assert "Finding severity changed" in out
    # _severity_from_payload prefers `severity` then `new_severity` — must use new_severity here
    assert "(critical)" in out


def test_summary_line_exploit_availability_changed_includes_cve_and_target():
    out = _summary_line(_exploit_event())
    assert "Exploit availability changed for CVE-2025-1111" in out
    assert "public" in out


def test_summary_line_anomaly_includes_scanner_and_multiplier():
    out = _summary_line(_anomaly_event())
    assert "Anomaly" in out
    assert "sast" in out
    assert "3.5" in out


def test_summary_line_cve_published_includes_cve_and_severity():
    out = _summary_line({
        "event_type": "intel.cve_published",
        "event_id": "ev-5",
        "org_id": "acme-org",
        "payload": {"cve_id": "CVE-2025-2222", "severity": "high"},
    })
    assert "CVE published: CVE-2025-2222" in out
    assert "(high)" in out


def test_summary_line_unknown_event_falls_back_to_title_case_of_event_type():
    # Lock the fallback path — an unrecognised event type must still produce
    # a non-empty summary so the audit dashboard isn't blank.
    out = _summary_line({
        "event_type": "some.unknown.event",
        "org_id": "acme-org",
        "payload": {},
    })
    assert "acme-org" in out
    # _event_title's fallback substitutes "." with " " and Title-cases.
    assert "Some Unknown Event" in out


def test_summary_line_empty_event_returns_event_title_placeholder():
    out = _summary_line({})
    # event_type is "" so _event_title returns "" — only the bracketed org wrapping.
    assert out.startswith("[]")




def test_event_title_known_types_return_human_strings():
    assert _event_title("finding.created") == "New finding"
    assert _event_title("finding.severity_changed") == "Finding severity changed"
    assert _event_title("intel.exploit_availability_changed") == "Exploit availability changed"
    assert _event_title("intel.anomaly_detected") == "Anomaly detected"
    assert _event_title("intel.cve_published") == "CVE published"


def test_event_title_unknown_type_falls_back_to_title_case_replacement():
    assert _event_title("custom.alert") == "Custom Alert"




def test_payload_fields_finding_created_extracts_tool_and_severity():
    out = _payload_fields("finding.created", {"tool": "trivy", "severity": "high"})
    assert out == {"Tool": "trivy", "Severity": "high"}


def test_payload_fields_finding_created_omits_missing_fields():
    # Missing values must NOT leak as empty entries — the downstream renderer
    # would otherwise show "Tool: " with a blank.
    assert _payload_fields("finding.created", {}) == {}


def test_payload_fields_severity_changed_renders_arrow():
    out = _payload_fields("finding.severity_changed", {"old_severity": "low", "new_severity": "critical"})
    assert out == {"Severity change": "low → critical"}


def test_payload_fields_exploit_event_extracts_cve_and_availability():
    out = _payload_fields("intel.exploit_availability_changed", {
        "cve_id": "CVE-1", "new_availability": "weaponized",
    })
    assert out == {"CVE": "CVE-1", "Availability": "weaponized"}


def test_payload_fields_anomaly_renders_multiplier_with_x_prefix():
    out = _payload_fields("intel.anomaly_detected", {
        "scanner_type": "sca", "multiplier": 5, "window_count": 12,
    })
    assert out["Scanner"] == "sca"
    assert out["Multiplier"] == "×5"
    assert out["Count"] == "12"


def test_payload_fields_unknown_event_returns_empty_dict():
    # Locks current behaviour: unknown events don't crash the formatter, they
    # just contribute no extra fields beyond the summary line.
    assert _payload_fields("some.unknown.event", {"k": "v"}) == {}




def test_format_for_slack_returns_text_and_block_kit_structure():
    out = format_for_slack(_finding_created_event())

    assert "text" in out
    assert "blocks" in out
    assert isinstance(out["blocks"], list)

    block_types = [b.get("type") for b in out["blocks"]]
    # Block 0 header, block 1 summary section, then injected fields section,
    # then context (event id / org id / event type).
    assert block_types[0] == "header"
    assert "section" in block_types
    assert block_types[-1] == "context"


def test_format_for_slack_severity_emoji_matches_payload_severity():
    out = format_for_slack(_finding_created_event())
    header_text = out["blocks"][0]["text"]["text"]
    # "high" maps to the large_orange_circle emoji.
    assert ":large_orange_circle:" in header_text


def test_format_for_slack_no_payload_fields_skips_fields_block():
    # When _payload_fields returns empty, the slack formatter must NOT insert
    # a blank fields section — Slack rejects sections with empty `fields`.
    event = {
        "event_type": "unknown.event",
        "event_id": "ev-x",
        "org_id": "acme-org",
        "payload": {},
    }
    out = format_for_slack(event)
    # No fields block was inserted: only header + summary + context = 3 blocks.
    assert len(out["blocks"]) == 3


def test_format_for_slack_context_block_includes_event_id_and_type():
    out = format_for_slack(_finding_created_event())
    context = out["blocks"][-1]
    ctx_text = context["elements"][0]["text"]
    assert "ev-1" in ctx_text
    assert "finding.created" in ctx_text
    assert "acme-org" in ctx_text




def test_format_for_webhook_envelope_shape():
    # Locks the JSON envelope that webhook receivers serialise against.
    out = format_for_webhook(_finding_created_event())
    assert out["source"] == "aegis"
    assert out["event_id"] == "ev-1"
    assert out["event_type"] == "finding.created"
    assert out["org_id"] == "acme-org"
    assert out["timestamp_utc"] == "2026-06-16T00:00:00+00:00"
    assert "summary" in out
    assert out["payload"] == _finding_created_event()["payload"]


def test_format_for_webhook_missing_fields_default_to_empty_strings_and_dict():
    # The dispatcher constructs `raw` even when source fields are absent —
    # the formatter must not raise KeyError on missing keys.
    out = format_for_webhook({})
    assert out["event_id"] == ""
    assert out["event_type"] == ""
    assert out["org_id"] == ""
    assert out["payload"] == {}




def test_escape_mrkdwn_escapes_amp_lt_gt_in_documented_order():
    # Slack's documented order is & first, then < and >, so an already-present
    # entity isn't double-escaped.
    assert _escape_mrkdwn("<script> & </b>") == "&lt;script&gt; &amp; &lt;/b&gt;"


def test_format_for_slack_escapes_attacker_controlled_finding_title():
    # A finding title carrying mrkdwn control chars must appear escaped in the
    # Slack section, never as a raw injected link/format.
    event = {
        "event_type": "finding.created",
        "event_id": "ev-1",
        "org_id": "acme-org",
        "payload": {"severity": "high", "title": "<http://evil|click> & <b>x</b>"},
    }
    out = format_for_slack(event)
    summary_section = out["blocks"][1]["text"]["text"]
    assert "&lt;http://evil|click&gt;" in summary_section
    assert "&amp;" in summary_section
    assert "<b>" not in summary_section
    # Fallback text is mrkdwn-rendered too, so it must be escaped as well.
    assert "<b>" not in out["text"]


def test_format_for_slack_escapes_payload_field_values():
    # Untrusted values in the fields block must be escaped; static labels aren't.
    event = {
        "event_type": "finding.created",
        "event_id": "ev-1",
        "org_id": "acme-org",
        "payload": {"tool": "<img>&", "severity": "high"},
    }
    out = format_for_slack(event)
    fields_texts = " ".join(
        f["text"] for b in out["blocks"] if b.get("type") == "section"
        for f in b.get("fields", [])
    )
    assert "&lt;img&gt;&amp;" in fields_texts


def test_format_for_webhook_and_email_do_not_escape_mrkdwn():
    # Escaping is Slack-mrkdwn-specific — the webhook JSON envelope and the plain
    # email body must carry the raw finding text unchanged.
    event = {
        "event_type": "finding.created",
        "event_id": "ev-1",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {"severity": "high", "tool": "<img>&", "title": "<b>raw</b> & <i>"},
    }
    webhook_out = format_for_webhook(event)
    assert webhook_out["payload"]["title"] == "<b>raw</b> & <i>"
    assert "<b>raw</b>" in webhook_out["summary"]

    email_out = format_for_email(event)
    assert "<b>raw</b> & <i>" in email_out["body"]
    assert "<img>&" in email_out["body"]


def test_format_for_email_subject_includes_event_title_and_org():
    out = format_for_email(_finding_created_event())
    assert out["subject"] == "[Aegis] New finding — acme-org"


def test_format_for_email_body_has_summary_details_and_metadata():
    out = format_for_email(_finding_created_event())
    body = out["body"]
    # Summary line first
    assert "New finding" in body
    # Details block
    assert "Details:" in body
    assert "Tool: trivy" in body
    assert "Severity: high" in body
    # Trailing metadata
    assert "Event ID: ev-1" in body
    assert "Event type: finding.created" in body
    assert "Organisation: acme-org" in body
    assert "Timestamp: 2026-06-16T00:00:00+00:00" in body


def test_format_for_email_unknown_event_still_produces_valid_subject_and_body():
    out = format_for_email({
        "event_type": "custom.thing",
        "event_id": "ev-z",
        "org_id": "acme-org",
        "timestamp_utc": "2026-06-16T00:00:00+00:00",
        "payload": {},
    })
    assert out["subject"].startswith("[Aegis]")
    assert "acme-org" in out["body"]
