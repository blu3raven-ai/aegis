"""Unit tests for the SSE parser used by `aegis watch`."""

from __future__ import annotations

from aegis_cli.sse_client import parse_sse_lines, SseMessage


def _lines_from(raw: str) -> list[str]:
    # Mirrors what httpx.Response.iter_lines() yields: line text without
    # trailing newlines.  Splitting on \n preserves blank delimiter lines.
    return raw.split("\n")


def test_parses_single_event_with_json_payload() -> None:
    raw = (
        "id:1\n"
        "event:finding.created\n"
        "data:{\"event_id\":\"abc\",\"payload\":{\"finding_id\":\"f-1\",\"severity\":\"high\"}}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert len(messages) == 1
    msg = messages[0]
    assert isinstance(msg, SseMessage)
    assert msg.event_type == "finding.created"
    assert msg.event_id == "1"
    assert msg.data["payload"]["finding_id"] == "f-1"


def test_parses_multiple_events_separated_by_blank_lines() -> None:
    raw = (
        "event:finding.created\n"
        "data:{\"payload\":{\"finding_id\":\"f-1\"}}\n"
        "\n"
        "event:finding.closed\n"
        "data:{\"payload\":{\"finding_id\":\"f-2\"}}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert [m.event_type for m in messages] == ["finding.created", "finding.closed"]
    assert messages[0].data["payload"]["finding_id"] == "f-1"
    assert messages[1].data["payload"]["finding_id"] == "f-2"


def test_heartbeat_comments_are_ignored() -> None:
    raw = (
        ":heartbeat 1700000000\n"
        "\n"
        "event:finding.created\n"
        "data:{}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert len(messages) == 1
    assert messages[0].event_type == "finding.created"


def test_data_with_leading_space_is_stripped() -> None:
    # Per the SSE spec, a single leading space after the colon is consumed.
    raw = (
        "event:finding.created\n"
        "data: {\"k\":1}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert messages[0].data == {"k": 1}


def test_multiline_data_concatenates_with_newlines() -> None:
    raw = (
        "event:finding.created\n"
        "data:{\n"
        "data:\"k\":1\n"
        "data:}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert messages[0].data == {"k": 1}


def test_invalid_json_falls_back_to_raw_string() -> None:
    raw = (
        "event:finding.created\n"
        "data:not-json\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert messages[0].data == {"_raw": "not-json"}


def test_empty_block_is_dropped() -> None:
    raw = "\n\n\n"
    assert list(parse_sse_lines(_lines_from(raw))) == []


def test_carriage_return_stripped() -> None:
    raw = "event:finding.created\r\ndata:{}\r\n\r\n"
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert len(messages) == 1
    assert messages[0].event_type == "finding.created"


def test_unknown_field_names_are_ignored() -> None:
    raw = (
        "retry:5000\n"
        "event:finding.created\n"
        "weird:value\n"
        "data:{}\n"
        "\n"
    )
    messages = list(parse_sse_lines(_lines_from(raw)))
    assert len(messages) == 1
    assert messages[0].event_type == "finding.created"
