"""Reference-vector tests for the deterministic CVSS 3.1 base scorer."""
from __future__ import annotations

import pytest

from runner.verification.cvss import score


def _metrics(av, ac, pr, ui, s, c, i, a) -> dict[str, str]:
    return {"AV": av, "AC": ac, "PR": pr, "UI": ui, "S": s, "C": c, "I": i, "A": a}


# (metrics, expected_vector, expected_score) — hand-verified against the 3.1 spec.
CASES = [
    (_metrics("N", "L", "N", "N", "U", "H", "H", "H"),
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    (_metrics("L", "L", "N", "R", "U", "H", "H", "H"),
     "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 7.8),
    (_metrics("N", "L", "N", "N", "C", "H", "H", "H"),
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    (_metrics("N", "L", "N", "N", "U", "N", "N", "N"),
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize("metrics,vector,expected", CASES)
def test_reference_vectors(metrics, vector, expected):
    result = score(metrics)
    assert result is not None
    assert result[0] == vector
    assert result[1] == expected


@pytest.mark.parametrize("bad", [
    {},                                                        # empty
    {"AV": "N"},                                               # incomplete
    _metrics("X", "L", "N", "N", "U", "H", "H", "H"),          # invalid AV
    _metrics("N", "L", "N", "N", "U", "H", "H", "Z"),          # invalid A
    "not-a-dict",                                              # wrong type
])
def test_invalid_metrics_fail_closed(bad):
    assert score(bad) is None


def test_case_and_whitespace_normalised():
    m = {"AV": " n ", "AC": "l", "PR": "N", "UI": "N", "S": "u", "C": "h", "I": "H", "A": "H"}
    result = score(m)
    assert result is not None
    assert result[1] == 9.8
