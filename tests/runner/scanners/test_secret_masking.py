"""Secret display masking: prefer TruffleHog's Redacted when it is genuinely a
partial, fall back to a deterministic prefix mask, and never surface the full
raw secret."""
from __future__ import annotations

from runner.scanners.secrets.normalize import _mask_value, _safe_display


def test_mask_value_shows_short_prefix_plus_fixed_tail():
    # Long secret: at most 4 leading chars (recognisable token type) + fixed tail.
    out = _mask_value("ghp_" + "a" * 36)
    assert out.startswith("ghp_")
    assert out == "ghp_••••••••"
    assert "a" * 36 not in out


def test_mask_value_reveals_proportionally_less_for_short_secrets():
    assert _mask_value("abcdefghi") == "abc••••••••"   # 9 chars -> keep 3
    assert _mask_value("abcdef") == "ab••••••••"        # 6 chars -> keep 2
    assert _mask_value("ab") == "••••••••"              # too short -> nothing


def test_safe_display_prefers_trufflehog_redacted_when_genuinely_partial():
    raw = "AKIAIOSFODNN7EXAMPLE"
    # Redacted is present, shorter, and contains no full raw value -> use it.
    assert _safe_display(raw, [raw], "AKIA...MPLE") == "AKIA...MPLE"


def test_safe_display_falls_back_to_mask_when_redacted_missing():
    raw = "sk-livesupersecrettoken9999"
    assert _safe_display(raw, [raw], "") == _mask_value(raw)


def test_safe_display_rejects_redacted_that_leaks_the_raw_value():
    raw = "supersecret"
    # Some detectors set Redacted to the raw secret itself; never trust that.
    assert _safe_display(raw, [raw], raw) == _mask_value(raw)
    assert _safe_display(raw, [raw], "prefix-" + raw + "-suffix") == _mask_value(raw)


def test_safe_display_rejects_redacted_not_shorter_than_raw():
    raw = "abcd"
    assert _safe_display(raw, [raw], "wxyz") == _mask_value(raw)
