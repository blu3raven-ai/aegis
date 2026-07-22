"""Regression tests for extract_json_object."""
from __future__ import annotations

from runner.verification.agents.parsing import extract_json_object


def test_plain_object():
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_object_wrapped_in_prose():
    text = 'Here is my answer:\n{"verdict": "confirmed", "n": 2}\nDone.'
    assert extract_json_object(text) == {"verdict": "confirmed", "n": 2}


def test_widest_brace_span_for_nested():
    text = 'noise {"a": {"b": 1}} trailing'
    assert extract_json_object(text) == {"a": {"b": 1}}


def test_none_on_empty():
    assert extract_json_object("") is None
    assert extract_json_object(None) is None  # type: ignore[arg-type]


def test_none_on_no_object():
    assert extract_json_object("no json here") is None
    assert extract_json_object("[1, 2, 3]") is None  # array is not an object


def test_none_on_malformed():
    assert extract_json_object("{not valid json") is None
