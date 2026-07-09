"""Regression: the Scans tab must list runs for EVERY selectable scanner.

A hand-maintained _SUPPORTED_TOOLS once omitted iac_scanning + agent_scanning,
so those runs were dropped from the Scans tab even though they ran. It's now
derived from the canonical scanner set — this locks that in.
"""
from src.scans.models import _VALID_SCANNERS
from src.sources.scan_runs_resolvers import _SUPPORTED_TOOLS


def test_supported_tools_covers_every_selectable_scanner():
    assert _SUPPORTED_TOOLS == frozenset(_VALID_SCANNERS)
    # The two that were being dropped:
    assert "iac_scanning" in _SUPPORTED_TOOLS
    assert "agent_scanning" in _SUPPORTED_TOOLS
